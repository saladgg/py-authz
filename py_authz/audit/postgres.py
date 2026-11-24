import json
from datetime import datetime

import asyncpg

from py_authz.audit.base import AuditLogger
from py_authz.audit.types import AuditEvent
from py_authz.core.exceptions import ConfigurationError

_NOT_CONNECTED = (
    "PostgresAuditLogger is not connected — call `await logger.connect()` first, "
    "or use it as an async context manager: "
    "`async with PostgresAuditLogger(dsn) as logger: ...`"
)


class PostgresAuditLogger(AuditLogger):
    """
    See `storage/postgres.py:PostgresTenantStore`'s docstring — same
    lifecycle contract (async context manager, idempotent `connect()`,
    `close()` to release the pool).
    """

    def __init__(
        self,
        dsn: str,
        *,
        command_timeout: float | None = 5.0,
        pool_min_size: int = 10,
        pool_max_size: int = 10,
    ):
        """
        Args:
            command_timeout: seconds allowed for the pool to acquire a
                connection and for a single `execute()` to complete.
                Previously unset (no timeout at all), so a Postgres
                instance that hangs after accepting the TCP connection
                (rather than refusing it outright) could block a write
                indefinitely — and since audit writes run as background
                tasks (see `AuthzEngine._dispatch_audit_event`), each
                blocked write's task never completes, growing
                `_background_audit_tasks` without bound for as long as
                the outage lasts (see REL2-4). `None` restores the old,
                unbounded behavior.
        """
        self.dsn = dsn
        self.command_timeout = command_timeout
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            self.dsn,
            command_timeout=self.command_timeout,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def __aenter__(self) -> "PostgresAuditLogger":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED)
        return self._pool

    async def log(self, event: AuditEvent) -> None:
        pool = self._require_pool()

        # `reason_data` is `Any` (typically a dict) and the `audit_logs`
        # table's `reason_data` column is `jsonb` — asyncpg does not
        # auto-serialize Python dicts into JSON, so passing one straight
        # through as a bind parameter raised on the very first real write.
        # `None` stays `None` (a genuinely absent value, not the string
        # "null").
        reason_data = None if event.reason_data is None else json.dumps(event.reason_data)

        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                """
                    INSERT INTO audit_logs (
                        timestamp,
                        tenant_id,
                        user_id,
                        action,
                        resource,
                        allowed,
                        reason,
                        reason_data,
                        request_id
                    )
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
                """,
                event.timestamp,
                event.tenant_id,
                event.user_id,
                event.action,
                event.resource,
                event.allowed,
                event.reason,
                reason_data,
                event.request_id,
            )


class PostgresAuditQuery:
    """
    Read-side companion to `PostgresAuditLogger`, against the same
    `audit_logs` table (schema: `py_authz/storage/sql/0003_audit_logs.sql`,
    plus `0008_audit_logs_timestamp_idx.sql`'s plain `"timestamp"` index
    for queries with no `tenant_id` predicate).

    Kept as a separate class — not new methods on `PostgresAuditLogger` —
    so the write path `AuthzEngine` calls on every decision (and
    `PostgresAuditLogger`'s own existing tests) stay untouched (see CP-5).
    Same connection-lifecycle contract as `PostgresTenantStore`: use as
    an async context manager, or call `connect()`/`close()` manually.
    """

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 10,
        pool_max_size: int = 10,
        command_timeout: float | None = 5.0,
    ):
        """See `PostgresTenantStore.__init__` for the pool-sizing/timeout args."""
        self.dsn = dsn
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.command_timeout = command_timeout
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            self.dsn,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
            command_timeout=self.command_timeout,
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def __aenter__(self) -> "PostgresAuditQuery":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED.format(cls=type(self).__name__))
        return self._pool

    async def query(
        self,
        *,
        tenant_id: str | None = None,
        user_id: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        allowed: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[dict]:
        """
        Filter/page the audit trail, newest first.

        `limit`/`offset` (rather than a cursor/continuation token) to
        match `PostgresTenantStore.list_tenant_ids()`'s existing
        pagination convention instead of inventing a new shape (see CP-5).
        As with any offset-based pagination against a table under active
        insert, a page requested while new rows are being written can
        shift by however many rows landed since the previous page — the
        same caveat `list_tenant_ids()`'s own docstring accepts for the
        same tradeoff.

        Every filter argument is an exact match, ANDed together; `None`
        (the default) means "don't filter on this field". `since`/`until`
        bound `"timestamp"` inclusively on either side.

        Returns:
            list[dict]: rows ordered newest-first (`"timestamp" DESC, id
            DESC` — the `id` tiebreaker keeps ordering stable for rows
            sharing a timestamp, which a busy system can produce more
            than the microsecond resolution suggests). `reason_data` is
            decoded back into a `dict`/`list`/scalar (asyncpg round-trips
            `jsonb` as the raw JSON text `PostgresAuditLogger.log()`
            wrote, not an already-parsed value — see that method's own
            `json.dumps` comment) rather than left as a JSON string.
        """
        conditions: list[str] = []
        params: list = []

        def add_eq(column: str, value) -> None:
            params.append(value)
            conditions.append(f"{column} = ${len(params)}")

        if tenant_id is not None:
            add_eq("tenant_id", tenant_id)
        if user_id is not None:
            add_eq("user_id", user_id)
        if action is not None:
            add_eq("action", action)
        if resource is not None:
            add_eq("resource", resource)
        if allowed is not None:
            add_eq("allowed", allowed)
        if since is not None:
            params.append(since)
            conditions.append(f'"timestamp" >= ${len(params)}')
        if until is not None:
            params.append(until)
            conditions.append(f'"timestamp" <= ${len(params)}')

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        params.append(limit)
        limit_idx = len(params)
        params.append(offset)
        offset_idx = len(params)

        # `where`/`limit_idx`/`offset_idx` interpolated below are never
        # caller-controlled data — `where` is built above from a fixed
        # set of column names, and the `$N` indices are just positions
        # into `params` (bound separately via `conn.fetch(sql, *params)`)
        # — so this isn't the string-built-from-user-input pattern S608
        # exists to catch.
        sql = (
            'SELECT id, "timestamp", tenant_id, user_id, action, resource, '  # noqa: S608
            "allowed, reason, reason_data, request_id "
            f"FROM audit_logs {where} "
            f'ORDER BY "timestamp" DESC, id DESC LIMIT ${limit_idx} OFFSET ${offset_idx}'
        )

        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            rows = await conn.fetch(sql, *params)

        results = []
        for row in rows:
            record = dict(row)
            if record["reason_data"] is not None:
                record["reason_data"] = json.loads(record["reason_data"])
            results.append(record)
        return results

import base64
import binascii
import json
from collections.abc import Sequence
from datetime import datetime

import asyncpg

from py_authz.audit.base import AuditLogger
from py_authz.audit.types import AuditEvent
from py_authz.core.exceptions import ConfigurationError, InvalidAuthzRequest

_COLUMNS = (
    "timestamp",
    "tenant_id",
    "store_id",
    "user_id",
    "action",
    "resource",
    "allowed",
    "reason",
    "reason_data",
    "request_id",
)


def _record(event: AuditEvent) -> tuple:
    # `reason_data` is `Any` (typically a dict) and the column is `jsonb`.
    # asyncpg doesn't serialise Python objects into JSON on its own (a raw
    # dict raised on the first real write, REL-4). `None` stays `None`.
    reason_data = None if event.reason_data is None else json.dumps(event.reason_data)
    return (
        event.timestamp,
        event.tenant_id,
        event.store_id,
        event.user_id,
        event.action,
        event.resource,
        event.allowed,
        event.reason,
        reason_data,
        event.request_id,
    )


def encode_cursor(timestamp: datetime, row_id: int) -> str:
    """Opaque keyset cursor for the row a page ended on (REL3-15)."""
    raw = f"{timestamp.isoformat()}|{row_id}".encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def decode_cursor(cursor: str) -> tuple[datetime, int]:
    """Inverse of `encode_cursor`. Raises `InvalidAuthzRequest` if malformed."""
    try:
        raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
        ts, _, row_id = raw.rpartition("|")
        return datetime.fromisoformat(ts), int(row_id)
    except (binascii.Error, UnicodeDecodeError, ValueError) as exc:
        raise InvalidAuthzRequest("Invalid audit-log cursor") from exc


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
        await self.log_many([event])

    async def log_many(self, events: Sequence[AuditEvent]) -> None:
        """
        Write several events in one round trip (REL3-16): binary `COPY`
        into `audit_logs`, which is what `BatchingAuditLogger` flushes
        through. One event costs the same as the old single INSERT.
        """
        if not events:
            return
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.copy_records_to_table(
                "audit_logs",
                columns=_COLUMNS,
                records=[_record(e) for e in events],
                timeout=self.command_timeout,
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
        legacy_store_id: str | None = None,
        store_id: str | None = None,
        user_id: str | None = None,
        action: str | None = None,
        resource: str | None = None,
        allowed: bool | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
        limit: int = 50,
        offset: int = 0,
        before: tuple[datetime, int] | None = None,
    ) -> list[dict]:
        """
        Filter/page the audit trail, newest first.

        Every filter argument is an exact match, ANDed together; `None`
        (the default) means "don't filter on this field". `since`/`until`
        bound `"timestamp"` inclusively on either side.

        `legacy_store_id` (only with `tenant_id`) also matches rows written
        before migration 0009, which stored the tenant's store id in
        `tenant_id` and left `store_id` NULL (ARCH3-16). Pass the tenant's
        current store id.

        Paging: pass `before=(timestamp, id)` of the last row of the
        previous page (keyset pagination, REL3-15) — see `encode_cursor`/
        `decode_cursor`. It costs the same at any depth and doesn't shift
        when new rows arrive. `offset` still works but costs O(offset) and
        can repeat or skip rows on a table under insert.

        Returns:
            list[dict]: rows ordered `"timestamp" DESC, id DESC` (the `id`
            tiebreaker keeps rows sharing a timestamp in a stable order).
            `reason_data` is decoded back into a Python value (asyncpg
            returns `jsonb` as raw JSON text).
        """
        conditions: list[str] = []
        params: list = []

        def bind(value) -> str:
            params.append(value)
            return f"${len(params)}"

        if tenant_id is not None:
            if legacy_store_id is not None:
                conditions.append(
                    f"(tenant_id = {bind(tenant_id)} OR "
                    f"(store_id IS NULL AND tenant_id = {bind(legacy_store_id)}))"
                )
            else:
                conditions.append(f"tenant_id = {bind(tenant_id)}")
        for column, value in (
            ("store_id", store_id),
            ("user_id", user_id),
            ("action", action),
            ("resource", resource),
            ("allowed", allowed),
        ):
            if value is not None:
                conditions.append(f"{column} = {bind(value)}")
        if since is not None:
            conditions.append(f'"timestamp" >= {bind(since)}')
        if until is not None:
            conditions.append(f'"timestamp" <= {bind(until)}')
        if before is not None:
            ts, row_id = before
            conditions.append(f'("timestamp", id) < ({bind(ts)}, {bind(row_id)})')

        where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        limit_ref = bind(limit)
        offset_ref = bind(offset)

        # Only fixed column names and `$N` placeholders are interpolated;
        # every value is bound separately, so S608 doesn't apply.
        sql = (
            'SELECT id, "timestamp", tenant_id, store_id, user_id, action, '  # noqa: S608
            "resource, allowed, reason, reason_data, request_id "
            f"FROM audit_logs {where} "
            f'ORDER BY "timestamp" DESC, id DESC LIMIT {limit_ref} OFFSET {offset_ref}'
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

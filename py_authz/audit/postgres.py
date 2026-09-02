import json

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

    def __init__(self, dsn: str, *, command_timeout: float | None = 5.0):
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
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(self.dsn, command_timeout=self.command_timeout)

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

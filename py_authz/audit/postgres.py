import asyncpg

from py_authz.audit.base import AuditLogger
from py_authz.audit.types import AuditEvent


class PostgresAuditLogger(AuditLogger):
    def __init__(self, dsn: str):
        self.dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn)

    async def log(self, event: AuditEvent) -> None:
        async with self._pool.acquire() as conn:
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
                event.reason_data,
                event.request_id,
            )

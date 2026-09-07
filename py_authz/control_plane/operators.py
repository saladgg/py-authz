"""
Operator directory (CP-2): `operators` — a record that a given verified
OIDC `subject` has logged into the control panel before. This table
gates nothing; an operator's actual permissions live entirely in the
dogfooded RBAC OpenFGA store (see `rbac_model.py`). It exists so a
"who has ever logged in" listing (e.g. an Operators & Roles screen
picking a subject to grant a role to) has somewhere to read from, since
the RBAC store itself only ever records grants, never identities that
hold none yet.
"""

from dataclasses import dataclass
from datetime import datetime

import asyncpg

from py_authz.core.exceptions import ConfigurationError

_NOT_CONNECTED = (
    "OperatorStore is not connected — call `await store.connect()` first, "
    "or use it as an async context manager."
)


@dataclass(frozen=True)
class Operator:
    id: int
    subject: str
    email: str | None
    created_at: datetime


class OperatorStore:
    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 5,
        pool_max_size: int = 5,
        command_timeout: float | None = 5.0,
    ):
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

    async def __aenter__(self) -> "OperatorStore":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED)
        return self._pool

    async def record_login(self, *, subject: str, email: str | None) -> Operator:
        """
        Upsert: record that `subject` has just authenticated. Called from
        the `get_current_principal` auth dependency on every successful
        operator token validation (see `auth.py`) — cheap (`INSERT ...
        ON CONFLICT DO UPDATE`), and idempotent regardless of how often
        it's called for the same subject.
        """
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO operators (subject, email)
                VALUES ($1, $2)
                ON CONFLICT (subject) DO UPDATE
                    SET email = COALESCE(EXCLUDED.email, operators.email)
                RETURNING *
                """,
                subject,
                email,
            )
        return Operator(
            id=row["id"], subject=row["subject"], email=row["email"], created_at=row["created_at"]
        )

    async def list(self, *, limit: int = 100, offset: int = 0) -> list[Operator]:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            rows = await conn.fetch(
                "SELECT * FROM operators ORDER BY created_at ASC LIMIT $1 OFFSET $2", limit, offset
            )
        return [
            Operator(id=r["id"], subject=r["subject"], email=r["email"], created_at=r["created_at"])
            for r in rows
        ]

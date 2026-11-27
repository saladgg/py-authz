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

import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime

import asyncpg

from py_authz.core.exceptions import ConfigurationError

_NOT_CONNECTED = (
    "OperatorStore is not connected — call `await store.connect()` first, "
    "or use it as an async context manager."
)


_RECENT_LOGINS_MAX = 10_000


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
        login_interval: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        """
        Args:
            login_interval: `record_login` skips the upsert for a subject
                (with the same email) recorded less than this many seconds
                ago by this process (REL3-19). 0 records every call.
        """
        self.dsn = dsn
        self.login_interval = login_interval
        self._clock = clock
        #: subject -> (email, when recorded); bounded LRU.
        self._recent_logins: OrderedDict[str, tuple[str | None, float]] = OrderedDict()
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

    async def record_login(self, *, subject: str, email: str | None) -> Operator | None:
        """
        Upsert: record that `subject` has just authenticated. Called by
        `GET /auth/me`, which the panel hits on every page load. Skipped
        (returns `None`) when this process recorded the same subject and
        email within `login_interval` seconds, so a page load no longer
        costs a Postgres write (REL3-19).
        """
        now = self._clock()
        recent = self._recent_logins.get(subject)
        if recent is not None and recent[0] == email and now - recent[1] < self.login_interval:
            return None
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
        self._recent_logins[subject] = (email, now)
        self._recent_logins.move_to_end(subject)
        while len(self._recent_logins) > _RECENT_LOGINS_MAX:
            self._recent_logins.popitem(last=False)
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

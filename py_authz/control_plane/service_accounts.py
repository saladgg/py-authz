"""
Service accounts: data model + Postgres-backed CRUD (CP-3).

Backs `service_accounts` (`storage/sql/0005_service_accounts.sql`). Same
connection-lifecycle contract as `PostgresTenantStore`/`PostgresAuditQuery`
— async context manager, or manual `connect()`/`close()`.
"""

import uuid
from dataclasses import dataclass
from datetime import datetime

import asyncpg

from py_authz.control_plane.security import generate_secret, hash_secret
from py_authz.core.exceptions import ConfigurationError, InvalidAuthzRequest

_NOT_CONNECTED = (
    "ServiceAccountStore is not connected — call `await store.connect()` first, "
    "or use it as an async context manager."
)


@dataclass(frozen=True)
class ServiceAccount:
    """A service account row — never carries the secret itself, only
    `secret_hash` (and even that is omitted from every API response;
    see `routes/service_accounts.py`)."""

    id: str
    name: str
    description: str | None
    secret_hash: str
    scopes: list[str]
    created_by: str | None
    created_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None

    @property
    def is_revoked(self) -> bool:
        return self.revoked_at is not None


def _new_id() -> str:
    return f"sa_{uuid.uuid4().hex}"


class ServiceAccountStore:
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

    async def __aenter__(self) -> "ServiceAccountStore":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED)
        return self._pool

    @staticmethod
    def _from_row(row) -> ServiceAccount:
        return ServiceAccount(
            id=row["id"],
            name=row["name"],
            description=row["description"],
            secret_hash=row["secret_hash"],
            scopes=list(row["scopes"]),
            created_by=row["created_by"],
            created_at=row["created_at"],
            last_used_at=row["last_used_at"],
            revoked_at=row["revoked_at"],
        )

    async def create(
        self,
        *,
        name: str,
        description: str | None,
        scopes: list[str],
        created_by: str | None,
    ) -> tuple[ServiceAccount, str]:
        """
        Create a new service account.

        Returns:
            (ServiceAccount, secret): `secret` is the plaintext secret —
            returned exactly once, here, and never retrievable again
            (only `secret_hash` is persisted). Callers (see
            `routes/service_accounts.py`) must surface it to the caller
            in this exact response and nowhere else (never a log line,
            never `result_json` on a job row — see CP-17).
        """
        account_id = _new_id()
        secret = generate_secret(account_id)
        secret_hash = hash_secret(secret)

        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            try:
                row = await conn.fetchrow(
                    """
                    INSERT INTO service_accounts
                        (id, name, description, secret_hash, scopes, created_by)
                    VALUES ($1, $2, $3, $4, $5, $6)
                    RETURNING *
                    """,
                    account_id,
                    name,
                    description,
                    secret_hash,
                    scopes,
                    created_by,
                )
            except asyncpg.UniqueViolationError as exc:
                raise InvalidAuthzRequest(
                    f"A non-revoked service account named {name!r} already exists"
                ) from exc

        return self._from_row(row), secret

    async def rotate(self, account_id: str) -> tuple[ServiceAccount, str]:
        """
        Issue a new secret for an existing, non-revoked account —
        invalidates the old one (a fresh `secret_hash` overwrites it
        entirely; the old hash is not merely superseded, it's gone —
        see CP-17), same id.
        """
        secret = generate_secret(account_id)
        secret_hash = hash_secret(secret)

        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                """
                UPDATE service_accounts
                SET secret_hash = $2
                WHERE id = $1 AND revoked_at IS NULL
                RETURNING *
                """,
                account_id,
                secret_hash,
            )

        if row is None:
            raise InvalidAuthzRequest(f"No active service account with id {account_id!r}")

        return self._from_row(row), secret

    async def revoke(self, account_id: str) -> None:
        """
        Soft-delete: sets `revoked_at`, never deletes the row — past
        audit-log entries attributing actions to `service:<name>` remain
        meaningful. Idempotent: revoking an already-revoked or unknown
        account is a no-op.

        Also overwrites `secret_hash` with a hash of a fresh, discarded
        random value (see CP-17) — `_authenticate_service_account()`
        already refuses any request with `is_revoked` set regardless of
        `secret_hash`, but this means the *hash itself* stops verifying
        the real (possibly still-known-to-a-former-holder) secret too,
        not just the `revoked_at` gate in front of it. Belt-and-suspenders:
        a future code path that checks `verify_secret()` without also
        checking `is_revoked` still can't be tricked by the old secret.
        """
        secret_hash = hash_secret(generate_secret(account_id))
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                "UPDATE service_accounts SET revoked_at = now(), secret_hash = $2 "
                "WHERE id = $1 AND revoked_at IS NULL",
                account_id,
                secret_hash,
            )

    async def get(self, account_id: str) -> ServiceAccount | None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow("SELECT * FROM service_accounts WHERE id = $1", account_id)
        return self._from_row(row) if row else None

    async def list(self, *, limit: int = 100, offset: int = 0) -> list[ServiceAccount]:
        """Every account (revoked included — the UI distinguishes via
        `is_revoked`, matching `service_accounts` never hard-deleting a
        row)."""
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            rows = await conn.fetch(
                "SELECT * FROM service_accounts ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                limit,
                offset,
            )
        return [self._from_row(row) for row in rows]

    async def touch_last_used(self, account_id: str) -> None:
        """Best-effort — called on every successful authentication, not
        gated on the caller awaiting/handling failure specially."""
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                "UPDATE service_accounts SET last_used_at = now() WHERE id = $1", account_id
            )

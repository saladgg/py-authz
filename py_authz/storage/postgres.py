import asyncpg

from py_authz.core.exceptions import ConfigurationError

# Schema: see py_authz/storage/sql/0001_tenants.sql, 0002_tenant_models.sql
# (versioned SQL files, not a comment) — apply them with
# `py_authz.storage.schema.apply_schema(dsn)`.

_NOT_CONNECTED = (
    "{cls} is not connected — call `await store.connect()` first, or use it "
    "as an async context manager: `async with {cls}(dsn) as store: ...`"
)


class PostgresTenantStore:
    """
    PostgreSQL-backed tenant store.

    Use as an async context manager to guarantee the connection pool is
    created before use and released after:

        async with PostgresTenantStore(dsn) as store:
            await store.set("acme", "01H...")

    Or call `connect()`/`close()` manually for a longer-lived instance
    (e.g. held on `app.state` for a web app's lifetime) — `connect()` is
    idempotent, so it's safe to call more than once.
    """

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 10,
        pool_max_size: int = 10,
        command_timeout: float | None = 5.0,
    ):
        """
        Args:
            pool_min_size, pool_max_size: forwarded to `asyncpg.
                create_pool()`. Previously unset (asyncpg's own default of
                10/10 applied silently, with no way to tune it for the
                host application's actual concurrency needs).
            command_timeout: seconds allowed for the pool to acquire a
                connection and for a single query to complete. Previously
                unset (no timeout at all), so a Postgres instance under
                load, or a network partition after the initial TCP
                handshake, could block a call indefinitely instead of
                failing fast (see REL2-11).
        """
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

    async def __aenter__(self) -> "PostgresTenantStore":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED.format(cls=type(self).__name__))
        return self._pool

    async def get(self, tenant_id: str) -> str | None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                "SELECT store_id FROM tenants WHERE tenant_id = $1",
                tenant_id,
            )
            return row["store_id"] if row else None

    async def set(self, tenant_id: str, store_id: str) -> None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                """
                INSERT INTO tenants (tenant_id, store_id)
                VALUES ($1, $2)
                ON CONFLICT (tenant_id)
                DO UPDATE SET store_id = EXCLUDED.store_id
                """,
                tenant_id,
                store_id,
            )

    async def list_tenant_ids(self) -> list[str]:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            rows = await conn.fetch("SELECT tenant_id FROM tenants ORDER BY tenant_id")
            return [row["tenant_id"] for row in rows]


class PostgresModelRegistry:
    """See `PostgresTenantStore`'s docstring — same lifecycle contract."""

    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 10,
        pool_max_size: int = 10,
        command_timeout: float | None = 5.0,
    ):
        """See `PostgresTenantStore.__init__` (REL2-11)."""
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

    async def __aenter__(self) -> "PostgresModelRegistry":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED.format(cls=type(self).__name__))
        return self._pool

    async def get(self, tenant_id: str) -> str | None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                "SELECT model_id FROM tenant_models WHERE tenant_id = $1",
                tenant_id,
            )
            return row["model_id"] if row else None

    async def set(self, tenant_id: str, model_id: str) -> None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                """
                INSERT INTO tenant_models (tenant_id, model_id)
                VALUES ($1, $2)
                ON CONFLICT (tenant_id)
                DO UPDATE SET model_id = EXCLUDED.model_id
                """,
                tenant_id,
                model_id,
            )

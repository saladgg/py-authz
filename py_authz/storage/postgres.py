import asyncpg

"""

CREATE TABLE tenants (
    tenant_id TEXT PRIMARY KEY,
    store_id TEXT NOT NULL
);

CREATE TABLE tenant_models (
    tenant_id TEXT PRIMARY KEY,
    model_id TEXT NOT NULL
);

"""


class PostgresTenantStore:
    """
    PostgreSQL-backed tenant store.
    """

    def __init__(self, dsn: str):
        self.dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn)

    async def get(self, tenant_id: str) -> str | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT store_id FROM tenants WHERE tenant_id = $1",
                tenant_id,
            )
            return row["store_id"] if row else None

    async def set(self, tenant_id: str, store_id: str) -> None:
        async with self._pool.acquire() as conn:
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


class PostgresModelRegistry:
    def __init__(self, dsn: str):
        self.dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self):
        self._pool = await asyncpg.create_pool(self.dsn)

    async def get(self, tenant_id: str) -> str | None:
        async with self._pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT model_id FROM tenant_models WHERE tenant_id = $1",
                tenant_id,
            )
            return row["model_id"] if row else None

    async def set(self, tenant_id: str, model_id: str) -> None:
        async with self._pool.acquire() as conn:
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

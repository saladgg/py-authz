class HybridTenantStore:
    """
    Redis (cache) + Postgres (source of truth).

    Both `pg_store` and `redis_store` are expected to conform to the
    `TenantStore`-shaped contract: `get(tenant_id) -> str | None` and
    `set(tenant_id, store_id, ex=None) -> None` — i.e. they already
    return/accept plain `str`, not raw bytes. `RedisTenantStore`/
    `RedisModelRegistry` (`storage/redis.py`) satisfy this; a bare
    `redis.asyncio.Redis` client does not (it returns raw bytes from
    `get()` and its `set()`, while it does accept `ex`, isn't meant to be
    handed to this class directly) and should not be passed here.
    """

    def __init__(self, pg_store, redis_store):
        self.pg = pg_store
        self.redis = redis_store

    async def get(self, tenant_id: str):
        cached = await self.redis.get(tenant_id)
        if cached:
            return cached

        store_id = await self.pg.get(tenant_id)

        if store_id:
            await self.redis.set(tenant_id, store_id, ex=300)

        return store_id

    async def set(self, tenant_id: str, store_id: str):
        await self.pg.set(tenant_id, store_id)
        await self.redis.set(tenant_id, store_id, ex=300)

    async def list_tenant_ids(self) -> list[str]:
        """
        Delegates to Postgres — the source of truth. Redis is a
        TTL-bounded cache of individual lookups and is not guaranteed to
        have ever seen every tenant, so it can't be used to enumerate
        them.
        """
        return await self.pg.list_tenant_ids()

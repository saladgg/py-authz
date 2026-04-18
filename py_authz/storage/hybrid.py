class HybridTenantStore:
    """
    Redis (cache) + Postgres (source of truth)
    """

    def __init__(self, pg_store, redis_store):
        self.pg = pg_store
        self.redis = redis_store

    async def get(self, tenant_id: str):
        cached = await self.redis.get(tenant_id)
        if cached:
            return cached.decode()

        store_id = await self.pg.get(tenant_id)

        if store_id:
            await self.redis.set(tenant_id, store_id, ex=300)

        return store_id

    async def set(self, tenant_id: str, store_id: str):
        await self.pg.set(tenant_id, store_id)
        await self.redis.set(tenant_id, store_id, ex=300)

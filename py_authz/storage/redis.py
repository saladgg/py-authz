from py_authz.utils.deps import require_redis

redis = require_redis()


class RedisTenantStore:
    def __init__(self, url: str):
        self.client = redis.from_url(url)

    async def get(self, tenant_id: str):
        return await self.client.get(f"tenant:{tenant_id}:store")

    async def set(self, tenant_id: str, store_id: str):
        await self.client.set(f"tenant:{tenant_id}:store", store_id)


class RedisModelRegistry:
    def __init__(self, url: str):
        self.client = redis.from_url(url)

    async def get(self, tenant_id: str):
        return await self.client.get(f"tenant:{tenant_id}:model")

    async def set(self, tenant_id: str, model_id: str):
        await self.client.set(f"tenant:{tenant_id}:model", model_id)

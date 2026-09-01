from py_authz.utils.deps import require_redis

redis = require_redis()


class RedisTenantStore:
    def __init__(self, url: str):
        self.client = redis.from_url(url)

    async def get(self, tenant_id: str) -> str | None:
        value = await self.client.get(f"tenant:{tenant_id}:store")

        if value is None:
            return None

        # redis-py returns bytes by default — decode so callers (e.g.
        # `MultiTenantAuthz.for_tenant`, `OpenFGAClient(store_id=...)`)
        # get the `str` they expect.
        return value.decode() if isinstance(value, bytes) else value

    async def set(self, tenant_id: str, store_id: str, ex: int | None = None) -> None:
        """
        Args:
            ex (Optional[int]):
                Expiry in seconds. `None` (the default) means the mapping
                never expires — the usual case for a tenant→store mapping.
                Accepting it at all is what lets this class compose with
                `HybridTenantStore`, which caches with a TTL.
        """
        await self.client.set(f"tenant:{tenant_id}:store", store_id, ex=ex)

    async def list_tenant_ids(self) -> list[str]:
        """
        Enumerate every tenant this store knows about via `SCAN` (not
        `KEYS` — `SCAN` doesn't block the server on a large keyspace).
        Note: if this store is used behind a `HybridTenantStore`, a
        tenant's mapping only lives here once it's been read/written at
        least once with a TTL still unexpired — prefer
        `HybridTenantStore.list_tenant_ids()` (delegating to Postgres,
        the source of truth) when composing the two.
        """
        prefix = "tenant:"
        suffix = ":store"
        tenant_ids = []

        async for key in self.client.scan_iter(match=f"{prefix}*{suffix}"):
            key_str = key.decode() if isinstance(key, bytes) else key
            tenant_ids.append(key_str[len(prefix) : -len(suffix)])

        return tenant_ids


class RedisModelRegistry:
    def __init__(self, url: str):
        self.client = redis.from_url(url)

    async def get(self, tenant_id: str) -> str | None:
        value = await self.client.get(f"tenant:{tenant_id}:model")

        if value is None:
            return None

        return value.decode() if isinstance(value, bytes) else value

    async def set(self, tenant_id: str, model_id: str, ex: int | None = None) -> None:
        await self.client.set(f"tenant:{tenant_id}:model", model_id, ex=ex)

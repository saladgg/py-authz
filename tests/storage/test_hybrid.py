import pytest

from py_authz.storage.hybrid import HybridTenantStore


class InMemoryPg:
    def __init__(self):
        self._data = {}

    async def get(self, tenant_id):
        return self._data.get(tenant_id)

    async def set(self, tenant_id, store_id):
        self._data[tenant_id] = store_id


class InMemoryRedis:
    """Mimics redis's bytes responses for get()."""

    def __init__(self):
        self._data: dict[str, bytes] = {}
        self.set_calls: list[tuple[str, str, int | None]] = []

    async def get(self, key):
        return self._data.get(key)

    async def set(self, key, value, ex=None):
        self._data[key] = value.encode() if isinstance(value, str) else value
        self.set_calls.append((key, value, ex))


@pytest.mark.asyncio
async def test_get_returns_cached_value_without_hitting_pg():
    pg = InMemoryPg()
    redis = InMemoryRedis()
    redis._data["t1"] = b"store-cached"

    store = HybridTenantStore(pg_store=pg, redis_store=redis)

    result = await store.get("t1")

    assert result == "store-cached"


@pytest.mark.asyncio
async def test_get_falls_through_to_pg_and_populates_cache():
    pg = InMemoryPg()
    await pg.set("t1", "store-from-pg")

    redis = InMemoryRedis()
    store = HybridTenantStore(pg_store=pg, redis_store=redis)

    result = await store.get("t1")

    assert result == "store-from-pg"
    assert redis.set_calls == [("t1", "store-from-pg", 300)]


@pytest.mark.asyncio
async def test_get_returns_none_when_missing_everywhere():
    store = HybridTenantStore(pg_store=InMemoryPg(), redis_store=InMemoryRedis())

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_set_writes_to_both_stores():
    pg = InMemoryPg()
    redis = InMemoryRedis()
    store = HybridTenantStore(pg_store=pg, redis_store=redis)

    await store.set("t1", "store-1")

    assert await pg.get("t1") == "store-1"
    assert redis.set_calls == [("t1", "store-1", 300)]

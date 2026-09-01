import pytest

from py_authz.storage import redis as redis_store_module
from py_authz.storage.hybrid import HybridTenantStore
from py_authz.storage.redis import RedisTenantStore


class InMemoryPg:
    def __init__(self):
        self._data = {}

    async def get(self, tenant_id):
        return self._data.get(tenant_id)

    async def set(self, tenant_id, store_id):
        self._data[tenant_id] = store_id

    async def list_tenant_ids(self):
        return list(self._data.keys())


class InMemoryRedis:
    """
    Mimics a `TenantStore`-shaped Redis wrapper (e.g. `RedisTenantStore`) —
    NOT a raw `redis.asyncio.Redis` client. Values are stored as bytes
    internally (to look at least somewhat like a real backing store) but
    `get()` returns already-decoded `str`, matching what `HybridTenantStore`
    actually composes with.
    """

    def __init__(self):
        self._data: dict[str, bytes] = {}
        self.set_calls: list[tuple[str, str, int | None]] = []

    async def get(self, key):
        value = self._data.get(key)
        return value.decode() if isinstance(value, bytes) else value

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


@pytest.mark.asyncio
async def test_list_tenant_ids_delegates_to_postgres():
    """
    Regression test for DX-5: Postgres is the source of truth, so
    enumeration must go through it — Redis is only a TTL-bounded cache of
    individual lookups and can't be relied on to have seen every tenant.
    """
    pg = InMemoryPg()
    await pg.set("t1", "store-1")
    await pg.set("t2", "store-2")

    store = HybridTenantStore(pg_store=pg, redis_store=InMemoryRedis())

    assert set(await store.list_tenant_ids()) == {"t1", "t2"}


# ----------------------------------------------------------------------
# Regression coverage for REL-1: compose HybridTenantStore with the real
# RedisTenantStore (not a bespoke double shaped only for this file) —
# this is exactly the composition the shipped `set()` signature mismatch
# broke, and exactly what neither class's own isolated unit tests caught.
# ----------------------------------------------------------------------


class FakeAsyncRedisClient:
    """A `redis-py`-shaped fake: `set()` takes `ex`, values round-trip as
    bytes — used only to avoid a real network dependency in this test."""

    def __init__(self):
        self.store: dict[str, bytes] = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value.encode() if isinstance(value, str) else value


class FakeRedisModule:
    def from_url(self, url):
        return FakeAsyncRedisClient()


@pytest.fixture
def real_redis_tenant_store(monkeypatch):
    monkeypatch.setattr(redis_store_module, "redis", FakeRedisModule())
    return RedisTenantStore("redis://fake")


@pytest.mark.asyncio
async def test_hybrid_store_composes_with_real_redis_tenant_store(real_redis_tenant_store):
    pg = InMemoryPg()
    store = HybridTenantStore(pg_store=pg, redis_store=real_redis_tenant_store)

    await store.set("t1", "store-1")

    assert await pg.get("t1") == "store-1"
    assert await real_redis_tenant_store.get("t1") == "store-1"

    # A second `get()` is served from the real Redis cache without
    # touching Postgres again.
    pg._data.clear()
    assert await store.get("t1") == "store-1"

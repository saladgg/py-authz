import pytest

from py_authz.storage import redis as redis_store_module
from py_authz.storage.redis import RedisModelRegistry, RedisTenantStore


class FakeAsyncRedis:
    def __init__(self):
        self.store: dict[str, str] = {}
        self.urls: list[str] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value):
        self.store[key] = value


class FakeRedisModule:
    def __init__(self):
        self.clients: list[FakeAsyncRedis] = []

    def from_url(self, url):
        client = FakeAsyncRedis()
        client.urls.append(url)
        self.clients.append(client)
        return client


@pytest.fixture
def patched_redis(monkeypatch):
    fake = FakeRedisModule()
    monkeypatch.setattr(redis_store_module, "redis", fake)
    return fake


@pytest.mark.asyncio
async def test_tenant_store_set_and_get(patched_redis):
    store = RedisTenantStore("redis://fake")

    await store.set("t1", "store-1")

    assert await store.get("t1") == "store-1"
    # key namespace is preserved
    assert "tenant:t1:store" in store.client.store


@pytest.mark.asyncio
async def test_tenant_store_get_returns_none_when_missing(patched_redis):
    store = RedisTenantStore("redis://fake")

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_model_registry_round_trip(patched_redis):
    reg = RedisModelRegistry("redis://fake")

    await reg.set("t1", "model-1")

    assert await reg.get("t1") == "model-1"
    assert "tenant:t1:model" in reg.client.store

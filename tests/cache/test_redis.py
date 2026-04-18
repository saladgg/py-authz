import pytest


class MockRedis:
    def __init__(self):
        self.store = {}

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value.encode()

    async def delete(self, key):
        self.store.pop(key, None)

    async def scan_iter(self, match=None):
        for key in list(self.store.keys()):
            yield key

    async def aclose(self):
        pass


@pytest.fixture
def redis_cache(monkeypatch):
    from py_authz.cache.redis import RedisCache

    mock = MockRedis()

    cache = RedisCache()

    # inject mock client
    cache._client = mock

    return cache


@pytest.mark.asyncio
async def test_redis_set_get(redis_cache):
    await redis_cache.set("key", True)
    assert await redis_cache.get("key") is True


@pytest.mark.asyncio
async def test_redis_delete(redis_cache):
    await redis_cache.set("key", True)
    await redis_cache.delete("key")
    assert await redis_cache.get("key") is None


@pytest.mark.asyncio
async def test_redis_clear(redis_cache):
    await redis_cache.set("k1", True)
    await redis_cache.set("k2", False)

    await redis_cache.clear()

    assert await redis_cache.get("k1") is None
    assert await redis_cache.get("k2") is None

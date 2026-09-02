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

    # `client=` (ARCH2-18) — the supported way to inject a test/host-owned
    # client, replacing the old private-attribute workaround.
    return RedisCache(client=mock)


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-18: `client=` lets a caller inject an
# existing Redis client instead of `RedisCache` always constructing its
# own from `url`.
# ----------------------------------------------------------------------


def test_redis_cache_client_injection_skips_url_construction(monkeypatch):
    from py_authz.cache import redis as redis_cache_module
    from py_authz.cache.redis import RedisCache

    def _fail_from_url(url):
        raise AssertionError("from_url must not be called when client= is given")

    monkeypatch.setattr(redis_cache_module.redis, "from_url", _fail_from_url)

    mock = MockRedis()
    cache = RedisCache(client=mock)

    assert cache._client is mock


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

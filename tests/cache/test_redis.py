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
        import fnmatch

        for key in list(self.store.keys()):
            if match is None or fnmatch.fnmatch(key, match):
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


# ----------------------------------------------------------------------
# count_keys() / delete_by_fragment() (CP-9)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_count_keys_counts_everything_under_prefix_by_default(redis_cache):
    await redis_cache.set("store1:1:a|1:v|1:d|1:1", True)
    await redis_cache.set("store2:1:b|1:v|1:d|1:1", True)

    assert await redis_cache.count_keys() == 2


@pytest.mark.asyncio
async def test_count_keys_narrows_by_fragment(redis_cache):
    await redis_cache.set("store1:1:a|1:v|1:d|1:1", True)
    await redis_cache.set("store2:1:b|1:v|1:d|1:1", True)

    assert await redis_cache.count_keys(fragment="store1:") == 1


@pytest.mark.asyncio
async def test_delete_by_fragment_deletes_only_matching_keys(redis_cache):
    await redis_cache.set("store1:1:a|1:v|1:d|1:1", True)
    await redis_cache.set("store2:1:b|1:v|1:d|1:1", True)

    deleted = await redis_cache.delete_by_fragment("store1:")

    assert deleted == 1
    assert await redis_cache.count_keys(fragment="store1:") == 0
    assert await redis_cache.count_keys(fragment="store2:") == 1


@pytest.mark.asyncio
async def test_delete_by_fragment_matches_a_fragment_mid_key():
    """A cache_namespace-scoped key looks like `<namespace>:<cache_key>`
    (see `AuthzEngine._scoped_cache_key`), so an `identity_prefix()`
    fragment needing to combine with a tenant namespace starts partway
    through the stored key — the match must not be anchored to the
    start."""
    from py_authz.cache.redis import RedisCache

    mock = MockRedis()
    cache = RedisCache(client=mock)
    user_fragment = "6:user:1|"  # AuthzRequest.identity_prefix("user:1")

    await cache.set(f"tenant-a:{user_fragment}5:view|8:document|1:1", True)
    await cache.set(f"tenant-a:{'6:user:2|'}5:view|8:document|1:1", True)

    deleted = await cache.delete_by_fragment(f"tenant-a:{user_fragment}")

    assert deleted == 1


@pytest.mark.asyncio
async def test_delete_by_fragment_rejects_empty_fragment(redis_cache):
    with pytest.raises(ValueError):
        await redis_cache.delete_by_fragment("")

import pytest

from tests.fake_redis import FakeRedis as MockRedis


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


# ----------------------------------------------------------------------
# SEC3-6 / REL3-18: prefix deletion, glob escaping, batched UNLINK
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_delete_by_prefix_matches_only_keys_starting_with_the_prefix(redis_cache):
    await redis_cache.set("store-a:6:user:1|x", True)
    await redis_cache.set("store-a:6:user:2|x", True)
    # The same text later in a key must not match a prefix delete.
    await redis_cache.set("store-b:12:doc:store-a:|x", True)

    deleted = await redis_cache.delete_by_prefix("store-a:")

    assert deleted == 2
    assert await redis_cache.get("store-b:12:doc:store-a:|x") is True


@pytest.mark.asyncio
async def test_glob_metacharacters_in_a_fragment_are_matched_literally(redis_cache):
    """`tenant_id="*"` used to wipe the whole cache."""
    await redis_cache.set("store-a:k1", True)
    await redis_cache.set("store-b:k2", True)

    assert await redis_cache.delete_by_fragment("*") == 0
    assert await redis_cache.delete_by_prefix("*") == 0
    assert await redis_cache.delete_by_fragment("store-?") == 0
    assert await redis_cache.count_keys() == 2


@pytest.mark.asyncio
async def test_bulk_delete_scans_with_a_large_count_and_unlinks_in_batches():
    from py_authz.cache import redis as redis_module
    from py_authz.cache.redis import RedisCache

    fake = MockRedis()
    cache = RedisCache(client=fake)
    for i in range(redis_module._DELETE_BATCH * 2 + 7):
        await cache.set(f"ns:{i}", True)

    calls: list[int] = []
    real_unlink = fake.unlink

    async def counting_unlink(*keys):
        calls.append(len(keys))
        return await real_unlink(*keys)

    fake.unlink = counting_unlink

    deleted = await cache.delete_by_prefix("ns:")

    assert deleted == redis_module._DELETE_BATCH * 2 + 7
    assert calls == [redis_module._DELETE_BATCH, redis_module._DELETE_BATCH, 7]
    assert fake.scan_counts[-1] == redis_module._SCAN_COUNT

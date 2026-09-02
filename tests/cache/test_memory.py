import asyncio

import pytest

from py_authz.cache.memory import InMemoryCache


@pytest.mark.asyncio
async def test_cache_set_get(cache):
    await cache.set("key", True)
    assert await cache.get("key") is True


@pytest.mark.asyncio
async def test_cache_expiry(cache):
    await cache.set("key", True, ttl=1)
    await asyncio.sleep(1.1)
    assert await cache.get("key") is None


@pytest.mark.asyncio
async def test_cache_delete(cache):
    await cache.set("key", True)
    await cache.delete("key")
    assert await cache.get("key") is None


@pytest.mark.asyncio
async def test_cache_clear(cache):
    await cache.set("k1", True)
    await cache.set("k2", False)

    await cache.clear()

    assert await cache.get("k1") is None
    assert await cache.get("k2") is None


# ----------------------------------------------------------------------
# Regression coverage for REL2-5: the cache used to have no size bound at
# all — a key written once and never read again stayed forever.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cache_evicts_least_recently_used_entry_when_over_cap():
    cache = InMemoryCache(max_size=2)

    await cache.set("k1", True)
    await cache.set("k2", True)
    await cache.set("k3", True)  # over cap -> evicts k1 (least recently used)

    assert await cache.get("k1") is None
    assert await cache.get("k2") is True
    assert await cache.get("k3") is True


@pytest.mark.asyncio
async def test_cache_get_refreshes_lru_order():
    cache = InMemoryCache(max_size=2)

    await cache.set("k1", True)
    await cache.set("k2", True)
    await cache.get("k1")  # k1 is now most-recently-used
    await cache.set("k3", True)  # evicts k2, not k1

    assert await cache.get("k1") is True
    assert await cache.get("k2") is None
    assert await cache.get("k3") is True


@pytest.mark.asyncio
async def test_cache_unbounded_when_max_size_is_none():
    cache = InMemoryCache(max_size=None)

    for i in range(50):
        await cache.set(f"k{i}", True)

    assert len(cache._store) == 50

import pytest
import asyncio


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
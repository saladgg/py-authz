import pytest

from py_authz.core.tenant_store import InMemoryTenantStore


@pytest.mark.asyncio
async def test_in_memory_store_get_returns_none_when_missing():
    store = InMemoryTenantStore()

    assert await store.get("t1") is None


@pytest.mark.asyncio
async def test_in_memory_store_round_trip():
    store = InMemoryTenantStore()

    await store.set("t1", "store-1")
    await store.set("t2", "store-2")

    assert await store.get("t1") == "store-1"
    assert await store.get("t2") == "store-2"


@pytest.mark.asyncio
async def test_in_memory_store_overwrites_existing_mapping():
    store = InMemoryTenantStore()

    await store.set("t1", "store-1")
    await store.set("t1", "store-2")

    assert await store.get("t1") == "store-2"

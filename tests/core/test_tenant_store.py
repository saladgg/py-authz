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


@pytest.mark.asyncio
async def test_list_tenant_ids_returns_empty_when_no_tenants():
    store = InMemoryTenantStore()

    assert await store.list_tenant_ids() == []


@pytest.mark.asyncio
async def test_list_tenant_ids_returns_every_known_tenant():
    """
    Regression test for DX-5: `py-authz migrate --all-tenants` needs a
    way to enumerate every tenant a `TenantStore` knows about.
    """
    store = InMemoryTenantStore()

    await store.set("t1", "store-1")
    await store.set("t2", "store-2")

    assert set(await store.list_tenant_ids()) == {"t1", "t2"}


@pytest.mark.asyncio
async def test_list_tenant_ids_supports_limit_and_offset():
    """REL2-17: pagination kwargs for a large tenant set."""
    store = InMemoryTenantStore()

    for tid in ["t3", "t1", "t2"]:
        await store.set(tid, f"store-{tid}")

    assert await store.list_tenant_ids(limit=2) == ["t1", "t2"]
    assert await store.list_tenant_ids(limit=2, offset=2) == ["t3"]

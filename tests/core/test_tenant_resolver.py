import pytest

from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.tenant_resolver import StaticTenantResolver, StoreBackedResolver
from py_authz.core.tenant_store import InMemoryTenantStore


@pytest.mark.asyncio
async def test_static_resolver_returns_mapped_store_id():
    resolver = StaticTenantResolver({"t1": "store-1", "t2": "store-2"})

    assert await resolver.resolve("t1") == "store-1"
    assert await resolver.resolve("t2") == "store-2"


@pytest.mark.asyncio
async def test_static_resolver_raises_tenant_not_found_error_on_unknown_tenant():
    """
    Regression test for SEC-4: resolvers must raise the dedicated
    `TenantNotFoundError`, not a bare `ValueError`, so
    `MultiTenantAuthz.for_tenant()` can distinguish "no such tenant yet"
    from an arbitrary resolver failure.
    """
    resolver = StaticTenantResolver({})

    with pytest.raises(TenantNotFoundError, match="Unknown tenant"):
        await resolver.resolve("missing")


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-14: `StoreBackedResolver` adapts any
# `TenantStore` into a `TenantResolver`, replacing the identical
# hand-rolled glue every multi-tenant example/consumer previously had to
# write itself.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_store_backed_resolver_returns_stored_value():
    store = InMemoryTenantStore()
    await store.set("t1", "store-1")

    resolver = StoreBackedResolver(store)

    assert await resolver.resolve("t1") == "store-1"


@pytest.mark.asyncio
async def test_store_backed_resolver_raises_tenant_not_found_error_on_unknown_tenant():
    resolver = StoreBackedResolver(InMemoryTenantStore())

    with pytest.raises(TenantNotFoundError, match="Unknown tenant"):
        await resolver.resolve("missing")

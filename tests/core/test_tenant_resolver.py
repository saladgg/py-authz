import pytest

from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.tenant_resolver import StaticTenantResolver


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

import pytest

from py_authz.core.tenant_resolver import StaticTenantResolver


@pytest.mark.asyncio
async def test_static_resolver_returns_mapped_store_id():
    resolver = StaticTenantResolver({"t1": "store-1", "t2": "store-2"})

    assert await resolver.resolve("t1") == "store-1"
    assert await resolver.resolve("t2") == "store-2"


@pytest.mark.asyncio
async def test_static_resolver_raises_on_unknown_tenant():
    resolver = StaticTenantResolver({})

    with pytest.raises(ValueError, match="Unknown tenant"):
        await resolver.resolve("missing")

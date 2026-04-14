import pytest


@pytest.mark.asyncio
async def test_authz_can(authz, identity, resource):
    result = await authz.can("viewer", identity, resource)
    assert result is True


@pytest.mark.asyncio
async def test_authz_require_success(authz, identity, resource):
    await authz.require("viewer", identity, resource)


@pytest.mark.asyncio
async def test_authz_require_failure():
    from tests.conftest import MockOpenFGAClient
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.api import Authz
    from py_authz.core.types import Identity, Resource
    from py_authz.core.exceptions import AuthorizationDenied

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
    )

    authz = Authz(engine)

    with pytest.raises(AuthorizationDenied):
        await authz.require(
            "viewer",
            Identity(id="user:1"),
            Resource(type="doc", id="1"),
        )
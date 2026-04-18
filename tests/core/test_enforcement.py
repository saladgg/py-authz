import pytest

from py_authz.core.exceptions import AuthorizationDenied, InvalidAuthzRequest


@pytest.mark.asyncio
async def test_enforce_allows_access(engine, authz_request):
    result = await engine.enforce(authz_request)
    assert result is True


@pytest.mark.asyncio
async def test_enforce_denies_access():
    from py_authz.core.enforcement import AuthzEngine
    from tests.conftest import MockOpenFGAClient

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
    )

    from py_authz.core.types import AuthzRequest, Identity, Resource

    request = AuthzRequest(
        identity=Identity(id="user:1"),
        action="view",
        resource=Resource(type="doc", id="1"),
    )

    result = await engine.enforce(request)
    assert result is False


@pytest.mark.asyncio
async def test_enforce_raise_on_denied():
    from py_authz.core.enforcement import AuthzEngine
    from tests.conftest import MockOpenFGAClient

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
        raise_on_denied=True,
    )

    from py_authz.core.types import AuthzRequest, Identity, Resource

    request = AuthzRequest(
        identity=Identity(id="user:1"),
        action="view",
        resource=Resource(type="doc", id="1"),
    )

    with pytest.raises(AuthorizationDenied):
        await engine.enforce(request)


@pytest.mark.asyncio
async def test_invalid_request_raises(engine):
    from py_authz.core.types import AuthzRequest, Identity, Resource

    bad_request = AuthzRequest(
        identity=Identity(id=""),
        action="",
        resource=Resource(type="", id=""),
    )

    with pytest.raises(InvalidAuthzRequest):
        await engine.enforce(bad_request)

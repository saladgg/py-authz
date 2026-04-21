import pytest

from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.types import AuthzExplanation, AuthzRequest, Identity, Resource
from tests.conftest import MockOpenFGAClient


@pytest.mark.asyncio
async def test_explain_returns_allowed_decision(authz_request):
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)

    result = await engine.explain(authz_request)

    assert isinstance(result, AuthzExplanation)
    assert result.allowed is True
    assert "viewer" in result.reason
    assert authz_request.resource.to_fga_object() in result.reason


@pytest.mark.asyncio
async def test_explain_returns_denied_decision(authz_request):
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=False), cache=None)

    result = await engine.explain(authz_request)

    assert result.allowed is False
    assert "No" in result.reason and "relation found" in result.reason


@pytest.mark.asyncio
async def test_explain_without_client_explain_method_sets_no_path(authz_request):
    # default MockOpenFGAClient has has_explain=False → no `explain` attr
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)

    result = await engine.explain(authz_request)

    assert result.path is None
    assert result.details is None


@pytest.mark.asyncio
async def test_explain_uses_client_explain_when_available(authz_request):
    details = {"resolution": ["direct-grant"]}
    client = MockOpenFGAClient(
        allowed=True,
        has_explain=True,
        explain_data=details,
    )
    engine = AuthzEngine(fga_client=client, cache=None)

    result = await engine.explain(authz_request)

    assert result.details == details
    # _extract_path falls back to a str() wrapper for the raw details
    assert result.path == [str(details)]


@pytest.mark.asyncio
async def test_explain_swallows_errors_from_client_explain(authz_request):
    client = MockOpenFGAClient(
        allowed=True,
        has_explain=True,
        explain_raises=RuntimeError("explain is broken"),
    )
    engine = AuthzEngine(fga_client=client, cache=None)

    result = await engine.explain(authz_request)

    # Explain failures must not break the higher-level decision
    assert result.allowed is True
    assert result.details is None
    assert result.path is None


@pytest.mark.asyncio
async def test_explain_validates_request():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    bad = AuthzRequest(
        identity=Identity(id=""),
        action="view",
        resource=Resource(type="doc", id="1"),
    )

    with pytest.raises(InvalidAuthzRequest):
        await engine.explain(bad)

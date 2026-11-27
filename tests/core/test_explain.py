import pytest

from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.types import AuthzExplanation, AuthzRequest, ContextualTuple, Identity, Resource
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


# ----------------------------------------------------------------------
# Regression coverage for ARCH-9: `explain()` must forward `context`/
# `contextual_tuples` from the request to the underlying client calls —
# previously dropped, so an explanation could silently describe a
# different check than the one actually being explained under ABAC/
# contextual-tuple conditions.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_explain_forwards_context_and_contextual_tuples_to_check(identity, resource):
    client = MockOpenFGAClient(allowed=True)
    engine = AuthzEngine(fga_client=client, cache=None)

    tuples = [ContextualTuple(user=identity.id, relation="owner", object=resource.to_fga_object())]
    request = AuthzRequest(
        identity=identity,
        action="viewer",
        resource=resource,
        context={"ip": "10.0.0.1"},
        contextual_tuples=tuple(tuples),
    )

    await engine.explain(request)

    assert client.last_context == {"ip": "10.0.0.1"}
    assert client.last_contextual_tuples == [t.to_fga() for t in tuples]


@pytest.mark.asyncio
async def test_explain_forwards_context_to_client_explain_when_supported(identity, resource):
    client = MockOpenFGAClient(allowed=True, has_explain=True, explain_data={"ok": True})
    engine = AuthzEngine(fga_client=client, cache=None)

    request = AuthzRequest(
        identity=identity,
        action="viewer",
        resource=resource,
        context={"ip": "10.0.0.1"},
    )

    await engine.explain(request)

    assert client.last_explain_context == {"ip": "10.0.0.1"}


@pytest.mark.asyncio
async def test_explain_falls_back_when_client_explain_predates_new_kwargs(authz_request):
    """An `explain` implementation with the old (user, relation, object)
    signature must still work — `explain()` retries without the new
    kwargs on `TypeError` instead of blowing up the whole call."""

    class OldStyleClient(MockOpenFGAClient):
        def __getattr__(self, name):
            if name == "explain":

                async def _old_explain(user, relation, object):
                    return {"old": True}

                return _old_explain
            return super().__getattr__(name)

    client = OldStyleClient(allowed=True)
    engine = AuthzEngine(fga_client=client, cache=None)

    result = await engine.explain(authz_request)

    assert result.details == {"old": True}


@pytest.mark.asyncio
async def test_explain_swallows_a_failure_of_the_legacy_signature_fallback_too(authz_request):
    """If the old-signature retry (after a `TypeError`) also fails, the
    explanation still comes back — just without details or a path."""
    calls = []

    class BrokenOldStyleClient(MockOpenFGAClient):
        def __getattr__(self, name):
            if name == "explain":

                async def _old_explain(user, relation, object):
                    calls.append((user, relation, object))
                    raise RuntimeError("expand endpoint down")

                return _old_explain
            return super().__getattr__(name)

    engine = AuthzEngine(fga_client=BrokenOldStyleClient(allowed=True), cache=None)

    result = await engine.explain(authz_request)

    assert result.allowed is True
    assert result.details is None
    assert result.path is None
    assert len(calls) == 1  # the fallback was attempted


@pytest.mark.asyncio
async def test_explain_path_is_none_when_details_cannot_be_rendered(authz_request):
    class Unprintable:
        def __str__(self):
            raise ValueError("cannot render")

    details = Unprintable()
    client = MockOpenFGAClient(allowed=True, has_explain=True, explain_data=details)
    engine = AuthzEngine(fga_client=client, cache=None)

    result = await engine.explain(authz_request)

    assert result.allowed is True
    assert result.path is None
    assert result.details is details

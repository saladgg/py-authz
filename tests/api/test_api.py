import pytest

from py_authz.core.types import ContextualTuple


@pytest.mark.asyncio
async def test_authz_can(authz, identity, resource):
    result = await authz.can("viewer", identity, resource)
    assert result is True


# ----------------------------------------------------------------------
# Regression coverage for DX-3: `can()`/`require()` must thread `context`/
# `contextual_tuples` through to `enforce()` — previously only the
# lower-level `engine.enforce(AuthzRequest(...))` path could do ABAC/
# contextual-tuple checks; the typed, `Relation`-based facade couldn't.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_can_forwards_context_to_engine(authz, mock_fga_client, identity, resource):
    await authz.can("viewer", identity, resource, context={"ip": "10.0.0.1"})

    assert mock_fga_client.last_context == {"ip": "10.0.0.1"}


@pytest.mark.asyncio
async def test_can_forwards_contextual_tuples_to_engine(authz, mock_fga_client, identity, resource):
    tuples = [ContextualTuple(user=identity.id, relation="owner", object=resource.to_fga_object())]

    await authz.can("viewer", identity, resource, contextual_tuples=tuples)

    assert mock_fga_client.last_contextual_tuples == [t.to_fga() for t in tuples]


@pytest.mark.asyncio
async def test_require_forwards_context_to_engine(authz, mock_fga_client, identity, resource):
    await authz.require("viewer", identity, resource, context={"time": "business-hours"})

    assert mock_fga_client.last_context == {"time": "business-hours"}


@pytest.mark.asyncio
async def test_require_forwards_contextual_tuples_to_engine(
    authz, mock_fga_client, identity, resource
):
    tuples = [ContextualTuple(user=identity.id, relation="owner", object=resource.to_fga_object())]

    await authz.require("viewer", identity, resource, contextual_tuples=tuples)

    assert mock_fga_client.last_contextual_tuples == [t.to_fga() for t in tuples]


@pytest.mark.asyncio
async def test_can_with_context_bypasses_cache(authz, mock_fga_client, identity, resource):
    """A contextual/ABAC check must not be served from — or pollute — the
    plain cache, since its result depends on per-request state."""
    # Warm the plain (non-contextual) cache entry.
    await authz.can("viewer", identity, resource)
    assert len(mock_fga_client.calls) == 1

    # A contextual call must hit the backend again, not reuse the cache.
    await authz.can("viewer", identity, resource, context={"ip": "10.0.0.1"})
    assert len(mock_fga_client.calls) == 2


@pytest.mark.asyncio
async def test_authz_require_success(authz, identity, resource):
    await authz.require("viewer", identity, resource)


@pytest.mark.asyncio
async def test_authz_require_failure():
    from py_authz.api import Authz
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.core.exceptions import AuthorizationDenied
    from py_authz.core.types import Identity, Resource
    from tests.conftest import MockOpenFGAClient

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


@pytest.mark.asyncio
async def test_require_and_enforce_are_independent_under_concurrency():
    """
    Regression test for SEC-6: `Authz.require()` used to flip
    `self._engine.raise_on_denied` on the shared engine, restoring it in
    a `finally` — under concurrent asyncio tasks sharing one engine, a
    `require()` call on one task could transiently affect a concurrent
    `enforce()` call on another (and vice versa) across the `await`
    inside `enforce()`. Runs many concurrent (enforce, require) pairs on
    one shared, denied engine: `enforce()` must always return `False`
    (never raise), and `require()` must always raise
    `AuthorizationDenied` (never silently return), regardless of how the
    two interleave.
    """
    import asyncio

    from py_authz.api import Authz
    from py_authz.cache.memory import InMemoryCache
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.core.exceptions import AuthorizationDenied
    from py_authz.core.types import Identity, Resource
    from tests.conftest import MockOpenFGAClient

    # A real cache (rather than None) gives enforce() a genuine `await`
    # point (cache.get/set) where concurrent tasks can actually interleave.
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=False), cache=InMemoryCache())
    authz = Authz(engine)

    user = Identity(id="user:1")

    async def call_enforce(n: int) -> bool:
        # A distinct resource id per task defeats the cache, keeping every
        # call on the real (denied) check path rather than a cache hit.
        return await authz.enforce("viewer", user, Resource(type="doc", id=f"enforce-{n}"))

    async def call_require(n: int) -> str:
        try:
            await authz.require("viewer", user, Resource(type="doc", id=f"require-{n}"))
            return "no-raise"
        except AuthorizationDenied:
            return "raised"

    enforce_tasks = [call_enforce(n) for n in range(25)]
    require_tasks = [call_require(n) for n in range(25)]

    enforce_results, require_results = await asyncio.gather(
        asyncio.gather(*enforce_tasks),
        asyncio.gather(*require_tasks),
    )

    assert all(result is False for result in enforce_results)
    assert all(result == "raised" for result in require_results)
    assert engine.raise_on_denied is False  # never mutated

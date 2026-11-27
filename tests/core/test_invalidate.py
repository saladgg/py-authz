import pytest

from py_authz.core.enforcement import AuthzEngine


@pytest.mark.asyncio
async def test_invalidate_removes_cached_decision(engine, authz_request, cache, mock_fga_client):
    # Populate cache
    assert await engine.enforce(authz_request) is True
    assert await cache.get(authz_request.cache_key()) is True

    # Invalidate
    await engine.invalidate(authz_request)

    assert await cache.get(authz_request.cache_key()) is None


@pytest.mark.asyncio
async def test_invalidate_forces_fga_on_next_call(engine, authz_request, mock_fga_client):
    await engine.enforce(authz_request)
    first_calls = len(mock_fga_client.calls)

    await engine.invalidate(authz_request)
    await engine.enforce(authz_request)

    assert len(mock_fga_client.calls) == first_calls + 1


@pytest.mark.asyncio
async def test_invalidate_noop_without_cache(authz_request, mock_fga_client):
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None)

    # Should not raise even though no cache is configured
    await engine.invalidate(authz_request)


@pytest.mark.asyncio
async def test_invalidate_missing_key_is_silent(engine, authz_request, cache):
    # Key was never set; should not raise
    await engine.invalidate(authz_request)
    assert await cache.get(authz_request.cache_key()) is None


# REL3-19: identity-wide invalidation and a configurable TTL.


def _req(user: str, action: str, res_id: str = "1"):
    from py_authz.core.types import AuthzRequest, Identity, Resource

    return AuthzRequest(
        identity=Identity(id=user), action=action, resource=Resource(type="doc", id=res_id)
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("namespace", [None, "store-1"])
async def test_invalidate_identity_drops_every_entry_for_that_identity_only(
    mock_fga_client, namespace
):
    from py_authz.cache.memory import InMemoryCache

    cache = InMemoryCache()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=cache, cache_namespace=namespace)
    for req in (_req("user:a", "view"), _req("user:a", "edit", "2"), _req("user:ab", "view")):
        await engine.enforce(req)

    await engine.invalidate_identity("user:a")

    keys = list(cache._store)
    assert len(keys) == 1 and "user:ab" in keys[0]


@pytest.mark.asyncio
async def test_invalidate_identity_clears_a_cache_without_prefix_delete(mock_fga_client):
    class PlainCache:
        def __init__(self):
            self.cleared = False

        async def get(self, key):
            return None

        async def set(self, key, value, ttl=60):
            pass

        async def delete(self, key):
            pass

        async def clear(self):
            self.cleared = True

    cache = PlainCache()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=cache)
    await engine.invalidate_identity("user:a")
    assert cache.cleared

    await AuthzEngine(fga_client=mock_fga_client).invalidate_identity("user:a")  # no cache: no-op


@pytest.mark.asyncio
async def test_cache_ttl_is_passed_to_the_cache(mock_fga_client):
    class TtlCache:
        ttls: list = []

        async def get(self, key):
            return None

        async def set(self, key, value, ttl=60):
            self.ttls.append(ttl)

    cache = TtlCache()
    await AuthzEngine(fga_client=mock_fga_client, cache=cache, cache_ttl=5).enforce(
        _req("user:a", "view")
    )
    assert cache.ttls == [5]


@pytest.mark.asyncio
async def test_grant_with_identity_invalidation_drops_implied_relations(mock_fga_client):
    """Granting `owner` must not leave a cached `viewer: false` behind."""
    from py_authz.api import Authz
    from py_authz.cache.memory import InMemoryCache
    from py_authz.core.types import Identity, Resource

    mock_fga_client.allowed = False
    engine = AuthzEngine(
        fga_client=mock_fga_client, cache=InMemoryCache(), invalidate_identity_on_write=True
    )
    authz = Authz(engine)
    alice, doc = Identity(id="user:alice"), Resource(type="doc", id="1")
    assert await authz.can("viewer", alice, doc) is False

    mock_fga_client.allowed = True
    await authz.grant(alice, "owner", doc)

    assert await authz.can("viewer", alice, doc) is True

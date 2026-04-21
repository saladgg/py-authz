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

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
async def test_enforce_raise_on_denied_per_call_override():
    """
    Regression test for SEC-6: a per-call `raise_on_denied` must override
    the engine's own configured default in both directions, without
    mutating the engine.
    """
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.core.types import AuthzRequest, Identity, Resource
    from tests.conftest import MockOpenFGAClient

    request = AuthzRequest(
        identity=Identity(id="user:1"),
        action="view",
        resource=Resource(type="doc", id="1"),
    )

    # Engine defaults to False — per-call True must still raise.
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=False), cache=None)
    with pytest.raises(AuthorizationDenied):
        await engine.enforce(request, raise_on_denied=True)
    assert engine.raise_on_denied is False  # engine's own default untouched

    # Engine defaults to True — per-call False must return False instead.
    engine2 = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False), cache=None, raise_on_denied=True
    )
    result = await engine2.enforce(request, raise_on_denied=False)
    assert result is False
    assert engine2.raise_on_denied is True  # engine's own default untouched


@pytest.mark.asyncio
async def test_enforce_records_metrics_when_injected():
    """
    Regression test for ARCH-6: `AuthzEngine` accepts an optional
    `metrics` dependency (matching `cache`/`audit_logger`'s existing
    injection pattern) and records check/allowed/denied/cache-hit
    counters plus a duration observation — previously `core/metrics.py`
    existed but was never wired to anything.
    """
    from py_authz.cache.memory import InMemoryCache
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.core.metrics import Metrics
    from py_authz.core.types import AuthzRequest, Identity, Resource
    from tests.conftest import MockOpenFGAClient

    metrics = Metrics()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=InMemoryCache(),
        metrics=metrics,
    )
    request = AuthzRequest(
        identity=Identity(id="user:1"), action="view", resource=Resource(type="doc", id="1")
    )

    await engine.enforce(request)  # cold — cache miss, real check

    assert metrics.counters["authz_check_total"] == 1
    assert metrics.counters["authz_allowed_total"] == 1
    assert "authz_denied_total" not in metrics.counters
    assert "authz_cache_hit_total" not in metrics.counters
    assert len(metrics.durations["authz_check_duration_ms"]) == 1

    await engine.enforce(request)  # warm — cache hit

    assert metrics.counters["authz_check_total"] == 2
    assert metrics.counters["authz_cache_hit_total"] == 1
    assert len(metrics.durations["authz_check_duration_ms"]) == 2


@pytest.mark.asyncio
async def test_enforce_metrics_are_a_no_op_when_not_configured(engine, authz_request):
    """No `metrics` was passed to `engine` — enforce() must not raise."""
    result = await engine.enforce(authz_request)
    assert result is True


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

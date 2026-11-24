import asyncio

import pytest

from py_authz.cache.memory import InMemoryCache
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource
from tests.conftest import MockOpenFGAClient as _BaseMockOpenFGAClient


class MockOpenFGAClient(_BaseMockOpenFGAClient):
    """Mock with a store_id attribute, which the audit logger reads."""

    def __init__(self, allowed: bool = True, store_id: str = "store-test"):
        super().__init__(allowed=allowed)
        self.store_id = store_id


class RecordingAuditLogger:
    def __init__(self):
        self.events: list = []

    async def log(self, event):
        self.events.append(event)


def _request(allowed_user="user:1"):
    return AuthzRequest(
        identity=Identity(id=allowed_user),
        action="view",
        resource=Resource(type="doc", id="1"),
    )


@pytest.mark.asyncio
async def test_cache_hit_short_circuits_fga_call():
    cache = InMemoryCache()
    fga = MockOpenFGAClient(allowed=True)
    engine = AuthzEngine(fga_client=fga, cache=cache)

    req = _request()

    # 1st call populates cache
    assert await engine.enforce(req) is True
    # 2nd call should be cache hit — fga called once in total
    assert await engine.enforce(req) is True
    assert len(fga.calls) == 1


@pytest.mark.asyncio
async def test_audit_logger_called_with_allowed_event():
    audit = RecordingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=None,
        audit_logger=audit,
    )

    await engine.enforce(_request())
    await engine.flush_audit_logs()  # audit writes are dispatched in the background

    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.allowed is True
    assert event.user_id == "user:1"
    assert event.action == "view"
    assert event.resource == "doc:1"
    assert "allowed via relation" in event.reason
    assert event.reason_data == {"cache_hit": False, "relation": "view"}


@pytest.mark.asyncio
async def test_audit_logger_called_on_cache_hit():
    """
    Regression test for ARCH2-1: a decision served from the cache is a
    real access decision and must be audit-logged like any other — this
    used to be a dead code path, since the audit dispatch was inlined
    only on the live-OpenFGA-check branch of `enforce()`.
    """
    audit = RecordingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=InMemoryCache(),
        audit_logger=audit,
    )

    req = _request()

    await engine.enforce(req)  # populates the cache
    await engine.enforce(req)  # served from the cache
    await engine.flush_audit_logs()

    assert len(audit.events) == 2
    first, second = audit.events
    assert first.reason_data == {"cache_hit": False, "relation": "view"}
    assert second.reason_data == {"cache_hit": True, "relation": "view"}
    assert second.allowed is True


@pytest.mark.asyncio
async def test_audit_logger_called_with_denied_event():
    audit = RecordingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
        audit_logger=audit,
    )

    await engine.enforce(_request())
    await engine.flush_audit_logs()

    assert audit.events[0].allowed is False
    assert "no matching relation" in audit.events[0].reason


@pytest.mark.asyncio
async def test_enforce_survives_audit_logger_failure():
    """
    Regression test for SEC-3: an unhealthy audit sink must never affect
    the enforcement decision, and must never propagate out of `enforce()`.
    """

    class FailingAuditLogger:
        def __init__(self):
            self.call_count = 0

        async def log(self, event):
            self.call_count += 1
            raise RuntimeError("audit sink is down")

    audit = FailingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=None,
        audit_logger=audit,
    )

    result = await engine.enforce(_request())
    assert result is True

    # The background audit task runs (and fails) once flushed; the
    # decision above must already have been unaffected either way.
    await engine.flush_audit_logs()
    assert audit.call_count == 1


@pytest.mark.asyncio
async def test_enforce_denied_survives_audit_logger_failure():
    """Same as above, but for a denied decision with raise_on_denied."""

    class FailingAuditLogger:
        async def log(self, event):
            raise RuntimeError("audit sink is down")

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False),
        cache=None,
        audit_logger=FailingAuditLogger(),
        raise_on_denied=True,
    )

    from py_authz.core.exceptions import AuthorizationDenied

    with pytest.raises(AuthorizationDenied):
        await engine.enforce(_request())

    await engine.flush_audit_logs()


@pytest.mark.asyncio
async def test_cache_namespace_isolates_engines_sharing_one_cache_backend():
    """
    Regression test for SEC2-4: two `AuthzEngine`s pointed at different
    stores (tenants) but sharing one cache backend must never read back
    each other's cached decisions for an identical (identity, action,
    resource) triple. `cache_namespace` (typically the tenant's store_id)
    is what prevents that.
    """
    shared_cache = InMemoryCache()
    req = _request()

    tenant_a = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True, store_id="store-a"),
        cache=shared_cache,
        cache_namespace="store-a",
    )
    tenant_b = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=False, store_id="store-b"),
        cache=shared_cache,
        cache_namespace="store-b",
    )

    # Populate tenant A's cache with an "allowed" decision.
    assert await tenant_a.enforce(req) is True

    # Tenant B, sharing the same cache backend but with a different
    # namespace, must still see its own (denied) decision — not tenant
    # A's cached "allowed".
    assert await tenant_b.enforce(req) is False
    assert len(tenant_b.fga_client.calls) == 1  # actually checked, not cache-hit


@pytest.mark.asyncio
async def test_invalidate_respects_cache_namespace():
    cache = InMemoryCache()
    req = _request()

    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=cache,
        cache_namespace="tenant-x",
    )

    await engine.enforce(req)
    assert await cache.get(engine._scoped_cache_key(req)) is True

    await engine.invalidate(req)
    assert await cache.get(engine._scoped_cache_key(req)) is None


@pytest.mark.asyncio
async def test_background_audit_tasks_are_capped_under_backpressure():
    """
    Regression test for REL2-4: if the audit sink hangs (rather than
    failing fast), background audit tasks must not grow without bound —
    once `max_background_audit_tasks` writes are in flight, further
    writes are dropped (and logged) instead of queued indefinitely.
    """

    class HangingAuditLogger:
        def __init__(self):
            self.call_count = 0

        async def log(self, event):
            self.call_count += 1
            await asyncio.sleep(3600)  # never completes within the test

    audit = HangingAuditLogger()
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True),
        cache=None,
        audit_logger=audit,
        max_background_audit_tasks=3,
    )

    for i in range(10):
        await engine.enforce(_request(allowed_user=f"user:{i}"))

    # Let the 3 scheduled background tasks actually get a turn on the
    # event loop before checking whether they started running.
    await asyncio.sleep(0)

    assert len(engine._background_audit_tasks) == 3
    assert audit.call_count == 3  # the other 7 were dropped, not queued

    for task in list(engine._background_audit_tasks):
        task.cancel()


@pytest.mark.asyncio
async def test_enforce_survives_cache_get_failure():
    """
    Regression test for DX2-4: the cache is advisory, never load-bearing
    — a `get()` failure must degrade to a real OpenFGA check, not
    propagate and take down the decision (the same failure class already
    fixed for the audit logger, SEC-3, and Keycloak key rotation, SEC-1).
    """

    class RaisingCache:
        async def get(self, key):
            raise ConnectionError("cache is down")

        async def set(self, key, value, ttl=60):
            pass

    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=RaisingCache())

    assert await engine.enforce(_request()) is True


@pytest.mark.asyncio
async def test_enforce_survives_cache_set_failure():
    class RaisingSetCache:
        async def get(self, key):
            return None

        async def set(self, key, value, ttl=60):
            raise ConnectionError("cache is down")

    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=RaisingSetCache())

    assert await engine.enforce(_request()) is True


@pytest.mark.asyncio
async def test_concurrent_cache_misses_on_same_key_share_one_upstream_call():
    """
    Regression test for REL2-6: concurrent `enforce()` calls that miss the
    cache on the identical key (a stampede right after a flush/restart, or
    the instant a hot key's TTL expires) must coalesce into one shared
    OpenFGA `check()` call, not each independently call through.
    """

    class SlowCheckClient(MockOpenFGAClient):
        async def check(self, *args, **kwargs):
            await asyncio.sleep(0.05)  # force real overlap between callers
            return await super().check(*args, **kwargs)

    fga = SlowCheckClient(allowed=True)
    engine = AuthzEngine(fga_client=fga, cache=InMemoryCache())

    req = _request()
    results = await asyncio.gather(*(engine.enforce(req) for _ in range(10)))

    assert results == [True] * 10
    assert len(fga.calls) == 1  # coalesced into a single upstream check

    # The cache is actually populated afterward — a later, non-concurrent
    # call is a genuine cache hit.
    assert await engine.enforce(req) is True
    assert len(fga.calls) == 1


@pytest.mark.asyncio
async def test_cancelling_one_coalesced_caller_does_not_cancel_the_others():
    """
    Regression test for REL3-1: the coalesced upstream task is shared, so
    cancelling the caller that started it (client disconnect, request
    timeout) must not cancel it for every other caller waiting on the
    same key — they must still get the real decision, and the decision
    must still land in the cache.
    """
    gate = asyncio.Event()

    class GatedCheckClient(MockOpenFGAClient):
        async def check(self, *args, **kwargs):
            await gate.wait()
            return await super().check(*args, **kwargs)

    fga = GatedCheckClient(allowed=True)
    cache = InMemoryCache()
    engine = AuthzEngine(fga_client=fga, cache=cache)
    req = _request()

    owner = asyncio.create_task(engine.enforce(req))
    await asyncio.sleep(0)  # owner installs the in-flight task
    waiter = asyncio.create_task(engine.enforce(req))
    await asyncio.sleep(0)  # waiter coalesces onto it

    owner.cancel()
    with pytest.raises(asyncio.CancelledError):
        await owner

    gate.set()
    assert await waiter is True
    assert len(fga.calls) == 1

    # The shared check still finished and cached its result even though
    # the caller that started it is gone.
    assert await engine.enforce(req) is True
    assert len(fga.calls) == 1


@pytest.mark.asyncio
async def test_cancelling_a_coalesced_waiter_does_not_cancel_the_owner():
    gate = asyncio.Event()

    class GatedCheckClient(MockOpenFGAClient):
        async def check(self, *args, **kwargs):
            await gate.wait()
            return await super().check(*args, **kwargs)

    engine = AuthzEngine(fga_client=GatedCheckClient(allowed=True), cache=InMemoryCache())
    req = _request()

    owner = asyncio.create_task(engine.enforce(req))
    await asyncio.sleep(0)
    waiter = asyncio.create_task(engine.enforce(req))
    await asyncio.sleep(0)

    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter

    gate.set()
    assert await owner is True


@pytest.mark.asyncio
async def test_concurrent_cache_misses_on_different_keys_each_call_upstream():
    """Coalescing must be per-key — distinct requests must never share
    (or block on) each other's upstream call."""
    fga = MockOpenFGAClient(allowed=True)
    engine = AuthzEngine(fga_client=fga, cache=InMemoryCache())

    requests = [_request(allowed_user=f"user:{i}") for i in range(5)]
    results = await asyncio.gather(*(engine.enforce(r) for r in requests))

    assert results == [True] * 5
    assert len(fga.calls) == 5


@pytest.mark.asyncio
async def test_invalid_request_variants_all_raise():
    from py_authz.core.exceptions import InvalidAuthzRequest

    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)

    cases = [
        AuthzRequest(
            identity=Identity(id=""),
            action="view",
            resource=Resource(type="doc", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="",
            resource=Resource(type="doc", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="view",
            resource=Resource(type="", id="1"),
        ),
        AuthzRequest(
            identity=Identity(id="user:1"),
            action="view",
            resource=Resource(type="doc", id=""),
        ),
    ]

    for req in cases:
        with pytest.raises(InvalidAuthzRequest):
            await engine.enforce(req)

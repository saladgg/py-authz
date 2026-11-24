import asyncio

import pytest

import py_authz.api as api_module
from py_authz.api import MultiTenantAuthz
from py_authz.core.exceptions import TenantNotFoundError


class FakeResolver:
    def __init__(self, mapping: dict[str, str], error: Exception | None = None):
        self.mapping = mapping
        self.error = error
        self.calls: list[str] = []

    async def resolve(self, tenant_id: str) -> str:
        self.calls.append(tenant_id)
        if self.error:
            raise self.error
        return self.mapping[tenant_id]


class FakeManager:
    def __init__(self):
        self.provisioned: list[str] = []

    async def provision(self, tenant_id: str) -> str:
        self.provisioned.append(tenant_id)
        return f"store-for-{tenant_id}"


class FakeFGAClient:
    instances: list["FakeFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        self.closed = False
        FakeFGAClient.instances.append(self)

    @classmethod
    def for_tenant(cls, *, api_url, store_id=None, model_id=None, **kwargs):
        return cls(api_url=api_url, store_id=store_id, model_id=model_id)

    async def aclose(self) -> None:
        self.closed = True


class RecordingAuditLogger:
    def __init__(self):
        self.events: list = []

    async def log(self, event):
        self.events.append(event)


@pytest.fixture(autouse=True)
def patch_fga_client(monkeypatch):
    FakeFGAClient.instances = []
    monkeypatch.setattr(api_module, "OpenFGAClient", FakeFGAClient)


@pytest.mark.asyncio
async def test_for_tenant_resolves_and_builds_authz():
    resolver = FakeResolver({"t1": "store-1"})

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id="model-1",
        tenant_resolver=resolver,
    )

    authz = await mt.for_tenant("t1")

    assert authz is not None
    assert resolver.calls == ["t1"]
    assert FakeFGAClient.instances[0].store_id == "store-1"


@pytest.mark.asyncio
async def test_for_tenant_caches_authz_instance():
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    first = await mt.for_tenant("t1")
    second = await mt.for_tenant("t1")

    assert first is second
    # resolver only called on first access
    assert resolver.calls == ["t1"]


@pytest.mark.asyncio
async def test_for_tenant_auto_provisions_on_tenant_not_found():
    resolver = FakeResolver({}, error=TenantNotFoundError("unknown"))
    manager = FakeManager()

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=manager,
    )

    authz = await mt.for_tenant("t-new")

    assert authz is not None
    assert manager.provisioned == ["t-new"]
    assert FakeFGAClient.instances[0].store_id == "store-for-t-new"


@pytest.mark.asyncio
async def test_for_tenant_reraises_when_no_manager():
    resolver = FakeResolver({}, error=TenantNotFoundError("unknown"))

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
    )

    with pytest.raises(TenantNotFoundError):
        await mt.for_tenant("t-unknown")


@pytest.mark.asyncio
async def test_for_tenant_does_not_auto_provision_on_arbitrary_resolver_error():
    """
    Regression test for SEC-4: a resolver failure that is NOT
    `TenantNotFoundError` (e.g. a transient DB/network error) must
    propagate as a hard failure, even when a `tenant_manager` is
    configured — it must never be silently reinterpreted as "this tenant
    doesn't exist yet" and trigger auto-provisioning of a new store.
    """
    resolver = FakeResolver({}, error=RuntimeError("db connection reset"))
    manager = FakeManager()

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=manager,
    )

    with pytest.raises(RuntimeError, match="db connection reset"):
        await mt.for_tenant("t-existing")

    assert manager.provisioned == []
    assert FakeFGAClient.instances == []


@pytest.mark.asyncio
async def test_aclose_closes_every_cached_tenant_client():
    """
    Regression test for REL-7: `MultiTenantAuthz` previously had no way to
    release the `OpenFGAClient`s (and their `httpx.AsyncClient` connection
    pools) it accumulates as it resolves more tenants — a real socket leak
    in any long-running process serving more than a handful of tenants.
    """
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    await mt.for_tenant("t1")
    await mt.for_tenant("t2")
    assert len(FakeFGAClient.instances) == 2

    await mt.aclose()

    assert all(client.closed for client in FakeFGAClient.instances)
    assert mt._cache == {}


@pytest.mark.asyncio
async def test_aclose_on_empty_cache_is_a_noop():
    resolver = FakeResolver({})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    await mt.aclose()  # must not raise

    assert mt._cache == {}


@pytest.mark.asyncio
async def test_authz_aclose_closes_underlying_fga_client():
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    authz = await mt.for_tenant("t1")
    await authz.aclose()

    assert FakeFGAClient.instances[0].closed is True


@pytest.mark.asyncio
async def test_authz_aclose_tolerates_a_client_with_no_aclose():
    """
    `Authz.aclose()` must not assume every `fga_client` implements
    `aclose()` — a caller could hand `AuthzEngine` an arbitrary
    duck-typed client that only implements `check()`.
    """
    from py_authz.api import Authz
    from py_authz.core.enforcement import AuthzEngine

    class ClientWithoutAclose:
        async def check(self, *args, **kwargs):
            return True

    authz = Authz(AuthzEngine(fga_client=ClientWithoutAclose()))

    await authz.aclose()  # must not raise


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-3 / SEC2-4: `MultiTenantAuthz` previously
# never forwarded `cache`/`audit_logger`/`metrics`/`raise_on_denied` into
# the `AuthzEngine`s it builds, so every tenant got none of those
# capabilities regardless of what was configured on `MultiTenantAuthz`
# itself. When a `cache` *is* forwarded, it must be namespaced per-tenant
# (by `store_id`) so it's safe to share one cache across every tenant.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_for_tenant_forwards_cache_audit_logger_metrics_and_raise_on_denied():
    from py_authz.cache.memory import InMemoryCache
    from py_authz.core.metrics import Metrics

    resolver = FakeResolver({"t1": "store-1"})
    cache = InMemoryCache()
    audit_logger = RecordingAuditLogger()
    metrics = Metrics()

    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        cache=cache,
        audit_logger=audit_logger,
        metrics=metrics,
        raise_on_denied=True,
    )

    authz = await mt.for_tenant("t1")

    assert authz._engine.cache is cache
    assert authz._engine.audit_logger is audit_logger
    assert authz._engine.metrics is metrics
    assert authz._engine.raise_on_denied is True


@pytest.mark.asyncio
async def test_for_tenant_namespaces_cache_by_resolved_store_id():
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    authz_t1 = await mt.for_tenant("t1")
    authz_t2 = await mt.for_tenant("t2")

    assert authz_t1._engine.cache_namespace == "store-1"
    assert authz_t2._engine.cache_namespace == "store-2"


@pytest.mark.asyncio
async def test_for_tenant_concurrent_first_resolution_constructs_exactly_one_client():
    """
    Regression test for ARCH2-9: concurrent first-callers for the same
    never-yet-cached tenant used to each independently resolve/provision/
    construct their own `OpenFGAClient` — all but the last writer to
    `self._cache` silently discarded (and never closed). A lock around
    the whole check-then-act sequence must make them share one result.
    """
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    results = await asyncio.gather(*(mt.for_tenant("t1") for _ in range(10)))

    assert len(FakeFGAClient.instances) == 1
    assert all(authz is results[0] for authz in results)
    assert resolver.calls == ["t1"]  # resolved exactly once, not 10 times


@pytest.mark.asyncio
async def test_for_tenant_evicts_least_recently_used_tenant_when_over_cap():
    """
    Regression test for SEC2-3: `MultiTenantAuthz`'s tenant cache used to
    be entirely unbounded by design — combined with tenant
    auto-provisioning accepting any caller-supplied `tenant_id`, an
    attacker-controlled stream of distinct tenant IDs could grow process
    memory/socket count without bound. `max_cached_tenants` now evicts
    the least-recently-used tenant (closing its `Authz`) once the cache
    would otherwise grow past it.
    """
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2", "t3": "store-3"})
    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        max_cached_tenants=2,
    )

    authz_t1 = await mt.for_tenant("t1")
    await mt.for_tenant("t2")
    await mt.for_tenant("t3")  # over the cap of 2 -> evicts t1 (least recently used)

    await asyncio.sleep(0)  # let the background eviction close() run

    assert list(mt._cache.keys()) == ["t2", "t3"]
    assert FakeFGAClient.instances[0].closed is True  # t1's client
    assert authz_t1 not in mt._cache.values()


@pytest.mark.asyncio
async def test_for_tenant_lru_touch_protects_recently_used_tenant_from_eviction():
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2", "t3": "store-3"})
    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        max_cached_tenants=2,
    )

    await mt.for_tenant("t1")
    await mt.for_tenant("t2")
    await mt.for_tenant("t1")  # touch t1 again -> t2 becomes least-recently-used
    await mt.for_tenant("t3")  # evicts t2, not t1

    await asyncio.sleep(0)

    assert list(mt._cache.keys()) == ["t1", "t3"]


@pytest.mark.asyncio
async def test_max_cached_tenants_none_disables_eviction():
    """Backward compatibility: the old unbounded-by-default behavior is
    still available as an explicit opt-in."""
    resolver = FakeResolver({"t1": "store-1", "t2": "store-2", "t3": "store-3"})
    mt = MultiTenantAuthz(
        api_url="http://fake",
        model_id=None,
        tenant_resolver=resolver,
        max_cached_tenants=None,
    )

    await mt.for_tenant("t1")
    await mt.for_tenant("t2")
    await mt.for_tenant("t3")

    assert len(mt._cache) == 3
    assert all(not c.closed for c in FakeFGAClient.instances)


@pytest.mark.asyncio
async def test_for_tenant_defaults_leave_engine_capabilities_unconfigured():
    """Backward compatibility: no new kwargs given -> same as before."""
    resolver = FakeResolver({"t1": "store-1"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)

    authz = await mt.for_tenant("t1")

    assert authz._engine.cache is None
    assert authz._engine.audit_logger is None
    assert authz._engine.metrics is None
    assert authz._engine.raise_on_denied is False


@pytest.mark.asyncio
async def test_evict_closes_the_cached_client_and_forces_re_resolution():
    """Regression test for REL3-4: after a tenant is deprovisioned and
    recreated under a new store, the cached instance must not keep
    routing to the deleted store."""
    resolver = FakeResolver({"t1": "store-old"})
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=resolver)
    old = await mt.for_tenant("t1")

    resolver.mapping["t1"] = "store-new"
    assert await mt.evict("t1") is True

    assert FakeFGAClient.instances[0].closed
    new = await mt.for_tenant("t1")
    assert new is not old
    assert new._engine.fga_client.store_id == "store-new"


@pytest.mark.asyncio
async def test_evict_of_an_uncached_tenant_is_a_noop():
    mt = MultiTenantAuthz(api_url="http://fake", model_id=None, tenant_resolver=FakeResolver({}))
    assert await mt.evict("never-seen") is False


@pytest.mark.asyncio
async def test_authz_aclose_flushes_in_flight_audit_writes_first():
    """REL3-8: shutdown used to close everything without awaiting
    background audit writes, dropping e.g. a just-made grant's audit row
    (with its reason/actor)."""
    from py_authz.api import Authz
    from py_authz.core.enforcement import AuthzEngine
    from py_authz.core.types import Identity, Resource

    landed = []
    gate = asyncio.Event()

    class SlowAuditLogger:
        async def log(self, event):
            await gate.wait()
            landed.append(event)

    class AllowClient:
        store_id = "s"

        async def check(self, **kwargs):
            return True

        async def aclose(self):
            pass

    authz = Authz(AuthzEngine(fga_client=AllowClient(), audit_logger=SlowAuditLogger()))
    await authz.can("viewer", Identity(id="user:1"), Resource(type="doc", id="1"))
    asyncio.get_running_loop().call_later(0.01, gate.set)

    await authz.aclose()

    assert len(landed) == 1

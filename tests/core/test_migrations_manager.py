import pytest

from py_authz.core import migrations_manager as mm_module
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.migrations_manager import MigrationManager
from py_authz.core.model_registry import InMemoryModelRegistry
from py_authz.core.tenant_store import InMemoryTenantStore


class FakeOpenFGAClient:
    instances: list["FakeOpenFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        self.aclose_called = False
        FakeOpenFGAClient.instances.append(self)

    @classmethod
    def for_tenant(cls, *, api_url, store_id=None, model_id=None, **kwargs):
        return cls(api_url=api_url, store_id=store_id, model_id=model_id)

    async def get_latest_model(self):
        return None

    async def aclose(self):
        self.aclose_called = True


class FakeModelSync:
    return_values: list[str] = []
    changed_values: list[bool] = []
    instances: list["FakeModelSync"] = []

    def __init__(self, fga_client):
        self.fga_client = fga_client
        self.last_sync_changed: bool | None = None
        FakeModelSync.instances.append(self)

    async def sync(self, force=False):
        self.last_sync_changed = (
            FakeModelSync.changed_values.pop(0) if FakeModelSync.changed_values else True
        )
        if FakeModelSync.return_values:
            return FakeModelSync.return_values.pop(0)
        return "model-new"


@pytest.fixture(autouse=True)
def patch_dependencies(monkeypatch):
    FakeOpenFGAClient.instances = []
    FakeModelSync.instances = []
    FakeModelSync.return_values = []
    FakeModelSync.changed_values = []
    monkeypatch.setattr(mm_module, "OpenFGAClient", FakeOpenFGAClient)
    monkeypatch.setattr(mm_module, "ModelSync", FakeModelSync)


@pytest.mark.asyncio
async def test_migrate_tenant_raises_when_tenant_unknown():
    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=InMemoryTenantStore(),
        model_registry=InMemoryModelRegistry(),
    )

    with pytest.raises(TenantNotFoundError, match="Tenant not found"):
        await mgr.migrate_tenant("missing")


@pytest.mark.asyncio
async def test_migrate_tenant_noop_when_model_unchanged():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()
    await registry.set("t1", "model-1")

    FakeModelSync.return_values = ["model-1"]
    FakeModelSync.changed_values = [False]  # ModelSync's own diff says "unchanged"

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    result = await mgr.migrate_tenant("t1")

    assert result == "model-1"
    # registry should not be updated since model didn't change
    assert await registry.get("t1") == "model-1"


@pytest.mark.asyncio
async def test_migrate_tenant_noop_derived_from_syncer_not_stale_registry():
    """
    Regression test for ARCH2-17: the noop/changed decision must come
    from `ModelSync.sync()`'s own real-time comparison against OpenFGA
    (`last_sync_changed`), not from comparing against
    `self.model_registry`'s separately-tracked, potentially-stale value.
    Here the registry has never been told about "model-new" at all (it's
    still empty), yet the migration must still report a noop because
    `syncer.last_sync_changed` says nothing changed.
    """
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()  # deliberately never seeded

    FakeModelSync.return_values = ["model-new"]
    FakeModelSync.changed_values = [False]

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    result = await mgr.migrate_tenant("t1")

    assert result == "model-new"
    # Never written, since it was a noop — model_registry is a
    # write-target on change only, never read back for the decision.
    assert await registry.get("t1") is None


@pytest.mark.asyncio
async def test_migrate_tenant_updates_registry_on_change():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()
    await registry.set("t1", "model-old")

    FakeModelSync.return_values = ["model-new"]
    FakeModelSync.changed_values = [True]

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    result = await mgr.migrate_tenant("t1")

    assert result == "model-new"
    assert await registry.get("t1") == "model-new"
    assert FakeOpenFGAClient.instances[0].store_id == "store-1"
    # Regression guard: each tenant's client must be closed, not leaked.
    assert FakeOpenFGAClient.instances[0].aclose_called is True


@pytest.mark.asyncio
async def test_migrate_all_iterates_tenants():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")
    await tenants.set("t2", "store-2")

    registry = InMemoryModelRegistry()

    FakeModelSync.return_values = ["model-a", "model-b"]
    FakeModelSync.changed_values = [True, True]

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    result = await mgr.migrate_all(["t1", "t2"])

    assert result.succeeded == {"t1": "model-a", "t2": "model-b"}
    assert result.failed == {}
    assert await registry.get("t1") == "model-a"
    assert await registry.get("t2") == "model-b"
    assert all(c.aclose_called for c in FakeOpenFGAClient.instances)


@pytest.mark.asyncio
async def test_migrate_all_isolates_per_tenant_failures():
    """
    Regression test for ARCH2-10: a failure on one tenant must not abort
    the batch or discard results already computed for other tenants —
    mirroring `AuthzEngine.bulk_enforce()`'s DX2-1 fix.
    """
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")
    await tenants.set("t2", "store-2")
    await tenants.set("t3", "store-3")

    registry = InMemoryModelRegistry()

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    async def selective_migrate_tenant(tenant_id):
        if tenant_id == "t2":
            raise RuntimeError("openfga unreachable")
        return f"model-for-{tenant_id}"

    mgr.migrate_tenant = selective_migrate_tenant  # type: ignore[method-assign]

    result = await mgr.migrate_all(["t1", "t2", "t3"])

    assert result.succeeded == {"t1": "model-for-t1", "t3": "model-for-t3"}
    assert set(result.failed) == {"t2"}
    assert isinstance(result.failed["t2"], RuntimeError)


@pytest.mark.asyncio
async def test_migrate_tenant_closes_client_even_when_sync_raises(monkeypatch):
    """Regression test: a client leak per tenant is especially bad in a
    command meant to loop over every tenant (see DX-5's `migrate`)."""
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    class RaisingModelSync:
        def __init__(self, fga_client):
            self.fga_client = fga_client

        async def sync(self, force=False):
            raise RuntimeError("openfga unreachable")

    monkeypatch.setattr(mm_module, "ModelSync", RaisingModelSync)

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=InMemoryModelRegistry(),
    )

    with pytest.raises(RuntimeError, match="openfga unreachable"):
        await mgr.migrate_tenant("t1")

    assert FakeOpenFGAClient.instances[0].aclose_called is True


# ----------------------------------------------------------------------
# dry_run_tenant / dry_run_all (REL2-10)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_dry_run_tenant_raises_when_tenant_unknown():
    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=InMemoryTenantStore(),
        model_registry=InMemoryModelRegistry(),
    )

    with pytest.raises(TenantNotFoundError):
        await mgr.dry_run_tenant("missing")


@pytest.mark.asyncio
async def test_dry_run_tenant_does_not_upload_or_persist(monkeypatch):
    """A dry run must never call `ModelSync`/upload a new model or touch
    `model_registry` — only `get_latest_model()` + a local diff."""
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()

    def _exploding_model_sync(*a, **kw):
        raise AssertionError("dry_run_tenant must not construct ModelSync")

    monkeypatch.setattr(mm_module, "ModelSync", _exploding_model_sync)

    mgr = MigrationManager(api_url="http://fake", tenant_store=tenants, model_registry=registry)

    would_change = await mgr.dry_run_tenant("t1")

    assert isinstance(would_change, bool)
    assert await registry.get("t1") is None  # nothing persisted
    assert FakeOpenFGAClient.instances[0].aclose_called is True


@pytest.mark.asyncio
async def test_dry_run_all_reports_every_tenant():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")
    await tenants.set("t2", "store-2")

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=InMemoryModelRegistry(),
    )

    results = await mgr.dry_run_all(["t1", "t2"])

    assert set(results) == {"t1", "t2"}
    assert all(isinstance(v, bool) for v in results.values())


@pytest.mark.asyncio
async def test_dry_run_batch_isolates_a_failing_tenant():
    """REL3-9: one missing tenant used to abort the whole preview with an
    ExceptionGroup, discarding every other tenant's result."""
    from py_authz.core.exceptions import TenantNotFoundError

    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")
    mgr = MigrationManager(
        api_url="http://fake", tenant_store=tenants, model_registry=InMemoryModelRegistry()
    )

    batch = await mgr.dry_run_batch(["t1", "ghost"])

    assert set(batch.would_change) == {"t1"}
    assert isinstance(batch.failed["ghost"], TenantNotFoundError)

    # The legacy API raises the real error, not a bare ExceptionGroup.
    with pytest.raises(TenantNotFoundError):
        await mgr.dry_run_all(["t1", "ghost"])

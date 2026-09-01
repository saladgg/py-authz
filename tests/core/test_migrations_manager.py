import pytest

from py_authz.core import migrations_manager as mm_module
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

    async def aclose(self):
        self.aclose_called = True


class FakeModelSync:
    return_values: list[str] = []
    instances: list["FakeModelSync"] = []

    def __init__(self, fga_client):
        self.fga_client = fga_client
        FakeModelSync.instances.append(self)

    async def sync(self, force=False):
        if FakeModelSync.return_values:
            return FakeModelSync.return_values.pop(0)
        return "model-new"


@pytest.fixture(autouse=True)
def patch_dependencies(monkeypatch):
    FakeOpenFGAClient.instances = []
    FakeModelSync.instances = []
    FakeModelSync.return_values = []
    monkeypatch.setattr(mm_module, "OpenFGAClient", FakeOpenFGAClient)
    monkeypatch.setattr(mm_module, "ModelSync", FakeModelSync)


@pytest.mark.asyncio
async def test_migrate_tenant_raises_when_tenant_unknown():
    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=InMemoryTenantStore(),
        model_registry=InMemoryModelRegistry(),
    )

    with pytest.raises(ValueError, match="Tenant not found"):
        await mgr.migrate_tenant("missing")


@pytest.mark.asyncio
async def test_migrate_tenant_noop_when_model_unchanged():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()
    await registry.set("t1", "model-1")

    FakeModelSync.return_values = ["model-1"]

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
async def test_migrate_tenant_updates_registry_on_change():
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    registry = InMemoryModelRegistry()
    await registry.set("t1", "model-old")

    FakeModelSync.return_values = ["model-new"]

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

    mgr = MigrationManager(
        api_url="http://fake",
        tenant_store=tenants,
        model_registry=registry,
    )

    result = await mgr.migrate_all(["t1", "t2"])

    assert result == {"t1": "model-a", "t2": "model-b"}
    assert await registry.get("t1") == "model-a"
    assert await registry.get("t2") == "model-b"
    assert all(c.aclose_called for c in FakeOpenFGAClient.instances)


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

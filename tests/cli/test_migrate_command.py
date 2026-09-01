import pytest

from py_authz.cli.commands import migrate as migrate_module
from py_authz.cli.commands.migrate import _build_backends, migrate_command
from py_authz.core.tenant_store import InMemoryTenantStore


class FakeMigrationManager:
    instances: list["FakeMigrationManager"] = []

    def __init__(self, *, api_url, tenant_store, model_registry):
        self.api_url = api_url
        self.tenant_store = tenant_store
        self.model_registry = model_registry
        self.migrate_all_calls: list[list[str]] = []
        FakeMigrationManager.instances.append(self)

    async def migrate_all(self, tenant_ids):
        self.migrate_all_calls.append(list(tenant_ids))
        return {tid: f"model-for-{tid}" for tid in tenant_ids}


@pytest.fixture(autouse=True)
def patch_migration_manager(monkeypatch):
    FakeMigrationManager.instances = []
    monkeypatch.setattr(migrate_module, "MigrationManager", FakeMigrationManager)


@pytest.mark.asyncio
async def test_build_backends_memory_returns_in_memory_pair():
    tenant_store, model_registry = await _build_backends("memory", None)

    assert isinstance(tenant_store, InMemoryTenantStore)
    await tenant_store.set("t1", "store-1")
    assert await tenant_store.get("t1") == "store-1"


@pytest.mark.asyncio
async def test_build_backends_rejects_unknown_backend():
    with pytest.raises(ValueError, match="Unknown --backend"):
        await _build_backends("carrier-pigeon", None)


@pytest.mark.asyncio
async def test_migrate_command_all_tenants_uses_store_enumeration(capsys, monkeypatch):
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")
    await tenants.set("t2", "store-2")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return tenants, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake", backend="memory")

    assert set(FakeMigrationManager.instances[0].migrate_all_calls[0]) == {"t1", "t2"}
    captured = capsys.readouterr()
    assert "t1: model-for-t1" in captured.out
    assert "t2: model-for-t2" in captured.out


@pytest.mark.asyncio
async def test_migrate_command_specific_tenants_skips_enumeration(monkeypatch):
    """Explicit --tenant flags must be used as-is, without ever calling
    `list_tenant_ids()` (the store may not even have those tenants yet
    if e.g. this is a dry run against a partially-seeded store)."""

    class ExplodingTenantStore(InMemoryTenantStore):
        async def list_tenant_ids(self):
            raise AssertionError("must not enumerate when explicit tenants are given")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return ExplodingTenantStore(), InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake", tenant_ids=["t1"])

    assert FakeMigrationManager.instances[0].migrate_all_calls == [["t1"]]


@pytest.mark.asyncio
async def test_migrate_command_prints_message_when_no_tenants_found(capsys, monkeypatch):
    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return InMemoryTenantStore(), InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake")

    assert FakeMigrationManager.instances == []
    captured = capsys.readouterr()
    assert "No tenants found" in captured.out

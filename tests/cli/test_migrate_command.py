import pytest

from py_authz.cli.commands import migrate as migrate_module
from py_authz.cli.commands.migrate import _build_backends, migrate_command
from py_authz.core.exceptions import ConfigurationError, ExternalServiceError
from py_authz.core.migrations_manager import MigrationBatchResult
from py_authz.core.tenant_store import InMemoryTenantStore


class FakeMigrationManager:
    instances: list["FakeMigrationManager"] = []

    def __init__(self, *, api_url, tenant_store, model_registry):
        self.api_url = api_url
        self.tenant_store = tenant_store
        self.model_registry = model_registry
        self.migrate_all_calls: list[list[str]] = []
        self.dry_run_all_calls: list[list[str]] = []
        self.failures: dict[str, Exception] = {}
        self.dry_run_results: dict[str, bool] = {}
        FakeMigrationManager.instances.append(self)

    async def migrate_all(self, tenant_ids):
        self.migrate_all_calls.append(list(tenant_ids))
        succeeded = {tid: f"model-for-{tid}" for tid in tenant_ids if tid not in self.failures}
        failed = {tid: self.failures[tid] for tid in tenant_ids if tid in self.failures}
        return MigrationBatchResult(succeeded=succeeded, failed=failed)

    async def dry_run_all(self, tenant_ids):
        self.dry_run_all_calls.append(list(tenant_ids))
        return {tid: self.dry_run_results.get(tid, True) for tid in tenant_ids}


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

    # `--all-tenants` (no explicit tenant_ids) now requires `yes=True` or
    # a TTY to confirm (see REL2-10) — pytest's stdin isn't a TTY.
    await migrate_command(api_url="http://fake", backend="memory", yes=True)

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

    # Explicit --tenant is not "all tenants" mode, so no confirmation is
    # needed even without `yes=True`.
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


# ----------------------------------------------------------------------
# Regression coverage for REL2-10: --dry-run and the --all-tenants
# confirmation gate.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_command_dry_run_reports_without_migrating(capsys, monkeypatch):
    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return InMemoryTenantStore(), InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake", tenant_ids=["t1"], dry_run=True)

    assert FakeMigrationManager.instances[0].dry_run_all_calls == [["t1"]]
    assert FakeMigrationManager.instances[0].migrate_all_calls == []
    captured = capsys.readouterr()
    assert "t1: would migrate" in captured.out


@pytest.mark.asyncio
async def test_migrate_command_all_tenants_refuses_without_yes_when_not_a_tty(monkeypatch):
    """
    Regression test for REL2-10: `--all-tenants` without `--yes` must not
    block forever on `input()` in a non-interactive context (pytest's
    stdin is never a TTY) — it must refuse explicitly instead.
    """
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return tenants, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)
    monkeypatch.setattr(migrate_module.sys.stdin, "isatty", lambda: False)

    with pytest.raises(ConfigurationError, match="non-interactively"):
        await migrate_command(api_url="http://fake", backend="memory")

    assert FakeMigrationManager.instances == []  # never even constructed


@pytest.mark.asyncio
async def test_migrate_command_all_tenants_proceeds_when_confirmed_interactively(
    capsys, monkeypatch
):
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return tenants, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)
    monkeypatch.setattr(migrate_module.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "y")

    await migrate_command(api_url="http://fake", backend="memory")

    assert FakeMigrationManager.instances[0].migrate_all_calls == [["t1"]]


@pytest.mark.asyncio
async def test_migrate_command_all_tenants_aborts_on_decline(monkeypatch):
    tenants = InMemoryTenantStore()
    await tenants.set("t1", "store-1")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return tenants, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)
    monkeypatch.setattr(migrate_module.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr("builtins.input", lambda prompt: "n")

    await migrate_command(api_url="http://fake", backend="memory")

    assert FakeMigrationManager.instances == []


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-10: per-tenant migration failures are
# reported (stderr) and turn into a summary `ExternalServiceError`,
# rather than a raw traceback aborting mid-batch.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_command_reports_partial_failures_and_raises(capsys, monkeypatch):
    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return InMemoryTenantStore(), InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    # Make the next constructed FakeMigrationManager report t2 as failed.
    original_init = FakeMigrationManager.__init__

    def init_with_failure(self, **kwargs):
        original_init(self, **kwargs)
        self.failures = {"t2": RuntimeError("openfga unreachable")}

    monkeypatch.setattr(FakeMigrationManager, "__init__", init_with_failure)

    with pytest.raises(ExternalServiceError, match="1 of 2"):
        await migrate_command(api_url="http://fake", tenant_ids=["t1", "t2"])

    captured = capsys.readouterr()
    assert "t1: model-for-t1" in captured.out
    assert "t2: FAILED - openfga unreachable" in captured.err


# ----------------------------------------------------------------------
# Regression coverage for REL2-8: backend connections must be released,
# even when the command raises.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_migrate_command_closes_backends_on_success(monkeypatch):
    class ClosableTenantStore(InMemoryTenantStore):
        def __init__(self):
            super().__init__()
            self.closed = False

        async def close(self):
            self.closed = True

    store = ClosableTenantStore()
    await store.set("t1", "store-1")

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return store, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake", tenant_ids=["t1"])

    assert store.closed is True


@pytest.mark.asyncio
async def test_migrate_command_closes_backends_even_when_no_tenants_found(monkeypatch):
    class ClosableTenantStore(InMemoryTenantStore):
        def __init__(self):
            super().__init__()
            self.closed = False

        async def close(self):
            self.closed = True

    store = ClosableTenantStore()

    async def fake_build_backends(backend, conn):
        from py_authz.core.model_registry import InMemoryModelRegistry

        return store, InMemoryModelRegistry()

    monkeypatch.setattr(migrate_module, "_build_backends", fake_build_backends)

    await migrate_command(api_url="http://fake")

    assert store.closed is True

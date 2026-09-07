from contextlib import asynccontextmanager

import pytest

from py_authz.core import tenant_manager as tm_module
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_store import InMemoryTenantStore


class FakeOpenFGAClient:
    instances: list["FakeOpenFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        self.create_store_calls: list[str] = []
        self.delete_store_calls: list[str] = []
        self.aclose_called = False
        self.create_store_error: Exception | None = None
        self.delete_store_error: Exception | None = None
        FakeOpenFGAClient.instances.append(self)

    @classmethod
    def for_tenant(cls, *, api_url, store_id=None, model_id=None, **kwargs):
        return cls(api_url=api_url, store_id=store_id, model_id=model_id)

    async def create_store(self, name):
        self.create_store_calls.append(name)
        if self.create_store_error is not None:
            raise self.create_store_error
        return f"store-for-{name}"

    async def delete_store(self, store_id):
        self.delete_store_calls.append(store_id)
        if self.delete_store_error is not None:
            raise self.delete_store_error

    async def aclose(self):
        self.aclose_called = True


class FakeModelSync:
    instances: list["FakeModelSync"] = []

    def __init__(self, fga_client):
        self.fga_client = fga_client
        self.sync_calls: list[bool] = []
        self.sync_error: Exception | None = None
        FakeModelSync.instances.append(self)

    async def sync(self, force=False):
        self.sync_calls.append(force)
        if self.sync_error is not None:
            raise self.sync_error
        return "model-id"


@pytest.fixture(autouse=True)
def patch_client_and_sync(monkeypatch):
    FakeOpenFGAClient.instances = []
    FakeModelSync.instances = []
    monkeypatch.setattr(tm_module, "OpenFGAClient", FakeOpenFGAClient)
    monkeypatch.setattr(tm_module, "ModelSync", FakeModelSync)


# -------------------------------------------------------------------
# Cached path
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provision_returns_cached_store_without_creating():
    store = InMemoryTenantStore()
    await store.set("t1", "existing-store")

    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    result = await mgr.provision("t1")

    assert result == "existing-store"
    assert FakeOpenFGAClient.instances == []
    assert FakeModelSync.instances == []


# -------------------------------------------------------------------
# Happy path
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provision_creates_store_syncs_model_and_persists():
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    result = await mgr.provision("t1")

    assert result == "store-for-t1"
    assert await store.get("t1") == "store-for-t1"

    client = FakeOpenFGAClient.instances[0]
    assert client.create_store_calls == ["t1"]
    assert client.store_id == "store-for-t1"
    assert client.aclose_called is True

    syncer = FakeModelSync.instances[0]
    assert syncer.fga_client is client
    assert syncer.sync_calls == [True]


# -------------------------------------------------------------------
# Client cleanup on failure
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provision_closes_client_when_sync_raises(monkeypatch):
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    original_init = FakeModelSync.__init__

    def init_with_error(self, fga_client):
        original_init(self, fga_client)
        self.sync_error = RuntimeError("sync failed")

    monkeypatch.setattr(FakeModelSync, "__init__", init_with_error)

    with pytest.raises(RuntimeError, match="sync failed"):
        await mgr.provision("t1")

    client = FakeOpenFGAClient.instances[0]
    assert client.aclose_called is True
    assert await store.get("t1") is None  # mapping not persisted on failure
    # Regression coverage for ARCH2-8: `create_store()` succeeded before
    # `sync()` failed, so the orphaned store must be cleaned up.
    assert client.delete_store_calls == ["store-for-t1"]


@pytest.mark.asyncio
async def test_provision_cleanup_failure_does_not_mask_original_exception(monkeypatch):
    """
    If the `delete_store()` cleanup call itself fails, the *original*
    exception (why provisioning failed in the first place) must still be
    what propagates — the cleanup is best-effort.
    """
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    original_init = FakeModelSync.__init__

    def init_with_error(self, fga_client):
        original_init(self, fga_client)
        self.sync_error = RuntimeError("sync failed")

    monkeypatch.setattr(FakeModelSync, "__init__", init_with_error)

    async def failing_delete_store(self, store_id):
        self.delete_store_calls.append(store_id)
        raise RuntimeError("cleanup also failed")

    monkeypatch.setattr(FakeOpenFGAClient, "delete_store", failing_delete_store)

    with pytest.raises(RuntimeError, match="sync failed"):
        await mgr.provision("t1")


@pytest.mark.asyncio
async def test_provision_propagates_and_closes_client_when_create_store_raises(monkeypatch):
    """
    Regression test for REL-5: `create_store()` failing — *before*
    `store_id` is ever assigned — must propagate its own exception
    cleanly, not mask it with `UnboundLocalError` from referencing an
    unset `store_id` in the finally/logging path.
    """
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    async def failing_create_store(self, name):
        self.create_store_calls.append(name)
        raise RuntimeError("cannot reach openfga")

    monkeypatch.setattr(FakeOpenFGAClient, "create_store", failing_create_store)

    with pytest.raises(RuntimeError, match="cannot reach openfga"):
        await mgr.provision("t1")

    client = FakeOpenFGAClient.instances[0]
    assert client.aclose_called is True
    assert await store.get("t1") is None
    # store_id was never assigned (create_store itself failed) — nothing
    # to clean up.
    assert client.delete_store_calls == []
    assert FakeModelSync.instances == []  # never reached model sync


# -------------------------------------------------------------------
# Lock behavior
# -------------------------------------------------------------------


class RecordingLockManager:
    def __init__(self):
        self.lock_keys: list[str] = []
        self.entered = False
        self.exited = False

    @asynccontextmanager
    async def lock(self, key):
        self.lock_keys.append(key)
        self.entered = True
        try:
            yield
        finally:
            self.exited = True


@pytest.mark.asyncio
async def test_provision_acquires_lock_when_lock_manager_provided():
    store = InMemoryTenantStore()
    lock_mgr = RecordingLockManager()
    mgr = TenantManager(
        api_url="http://fake",
        tenant_store=store,
        lock_manager=lock_mgr,
    )

    await mgr.provision("t1")

    assert lock_mgr.lock_keys == ["py_authz:provision:t1"]
    assert lock_mgr.entered and lock_mgr.exited


@pytest.mark.asyncio
async def test_provision_rechecks_store_under_lock():
    """
    If another caller provisions between our initial get() and lock
    acquisition, we must return their store_id and not create a new one.
    """
    store = InMemoryTenantStore()

    class PopulatingLockManager:
        @asynccontextmanager
        async def lock(self, key):
            # Simulate another worker winning the race
            await store.set("t1", "other-workers-store")
            yield

    mgr = TenantManager(
        api_url="http://fake",
        tenant_store=store,
        lock_manager=PopulatingLockManager(),
    )

    result = await mgr.provision("t1")

    assert result == "other-workers-store"
    assert FakeOpenFGAClient.instances == []  # no store created


# -------------------------------------------------------------------
# tenant_id validation (SEC2-3)
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_provision_rejects_tenant_id_with_disallowed_characters():
    """
    Regression test for SEC2-3: `tenant_id` can originate from
    request-derived input (e.g. `X-Tenant-ID` via `MultiTenantAuthz`) —
    an attacker-controlled string must be rejected before any lookup,
    lock acquisition, or store creation is attempted.
    """
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    with pytest.raises(InvalidAuthzRequest):
        await mgr.provision("../etc/passwd")

    assert FakeOpenFGAClient.instances == []


@pytest.mark.asyncio
async def test_provision_accepts_ordinary_tenant_ids():
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    for tenant_id in ["t1", "acme-corp", "tenant_42", "a.b.c"]:
        result = await mgr.provision(tenant_id)
        assert result == f"store-for-{tenant_id}"


@pytest.mark.asyncio
async def test_provision_honors_custom_tenant_id_pattern():
    store = InMemoryTenantStore()
    mgr = TenantManager(
        api_url="http://fake",
        tenant_store=store,
        tenant_id_pattern=r"^tenant-\d+$",
    )

    result = await mgr.provision("tenant-42")
    assert result == "store-for-tenant-42"

    with pytest.raises(InvalidAuthzRequest):
        await mgr.provision("not-matching")


# -------------------------------------------------------------------
# deprovision() (CP-4)
# -------------------------------------------------------------------


class FakeModelRegistry:
    def __init__(self):
        self.data: dict[str, str] = {}
        self.delete_calls: list[str] = []

    async def set(self, tenant_id, model_id):
        self.data[tenant_id] = model_id

    async def delete(self, tenant_id):
        self.delete_calls.append(tenant_id)
        self.data.pop(tenant_id, None)


@pytest.mark.asyncio
async def test_deprovision_deletes_store_and_mapping():
    store = InMemoryTenantStore()
    await store.set("t1", "store-1")
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    await mgr.deprovision("t1")

    assert await store.get("t1") is None
    client = FakeOpenFGAClient.instances[0]
    assert client.delete_store_calls == ["store-1"]
    assert client.aclose_called is True


@pytest.mark.asyncio
async def test_deprovision_also_cleans_model_registry_when_given():
    store = InMemoryTenantStore()
    await store.set("t1", "store-1")
    registry = FakeModelRegistry()
    await registry.set("t1", "model-1")
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    await mgr.deprovision("t1", model_registry=registry)

    assert registry.delete_calls == ["t1"]
    assert "t1" not in registry.data


@pytest.mark.asyncio
async def test_deprovision_unknown_tenant_is_a_noop():
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    await mgr.deprovision("never-provisioned")

    assert FakeOpenFGAClient.instances == []  # never even constructed a client


@pytest.mark.asyncio
async def test_deprovision_rejects_invalid_tenant_id():
    store = InMemoryTenantStore()
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    with pytest.raises(InvalidAuthzRequest):
        await mgr.deprovision("../etc/passwd")


@pytest.mark.asyncio
async def test_deprovision_leaves_mapping_intact_if_store_deletion_fails():
    store = InMemoryTenantStore()
    await store.set("t1", "store-1")
    mgr = TenantManager(api_url="http://fake", tenant_store=store)

    # Prime a client whose delete_store() will raise, by provisioning
    # first isn't needed — deprovision constructs its own client via the
    # patched FakeOpenFGAClient; configure the *next* instance to fail.
    original_delete_store = FakeOpenFGAClient.delete_store

    async def failing_delete_store(self, store_id):
        raise RuntimeError("openfga unreachable")

    FakeOpenFGAClient.delete_store = failing_delete_store
    try:
        with pytest.raises(RuntimeError, match="openfga unreachable"):
            await mgr.deprovision("t1")
    finally:
        FakeOpenFGAClient.delete_store = original_delete_store

    # The tenant is left exactly as provisioned — safe to retry.
    assert await store.get("t1") == "store-1"

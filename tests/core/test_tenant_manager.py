from contextlib import asynccontextmanager

import pytest

from py_authz.core import tenant_manager as tm_module
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_store import InMemoryTenantStore


class FakeOpenFGAClient:
    instances: list["FakeOpenFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        self.create_store_calls: list[str] = []
        self.aclose_called = False
        self.create_store_error: Exception | None = None
        FakeOpenFGAClient.instances.append(self)

    async def create_store(self, name):
        self.create_store_calls.append(name)
        if self.create_store_error is not None:
            raise self.create_store_error
        return f"store-for-{name}"

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

    assert FakeOpenFGAClient.instances[0].aclose_called is True
    assert await store.get("t1") is None  # mapping not persisted on failure


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

    assert FakeOpenFGAClient.instances[0].aclose_called is True
    assert await store.get("t1") is None
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

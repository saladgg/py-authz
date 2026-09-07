"""Tests for py_authz.control_plane.routes.models (CP-6): current-model
view, sync (dry-run + real), version history, and rollback.

`sync_model`/`rollback_model` construct a real `OpenFGAClient.for_tenant`
+ `ModelSync` internally (there's no injection point at the route level)
— monkeypatched at the module's own imported names, mirroring
`tests/core/test_tenant_manager.py`'s established pattern for the same
situation in `TenantManager.provision()`.
"""

from datetime import datetime

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.model_versions import ModelVersion
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.routes import models as models_routes
from py_authz.control_plane.settings import ControlPlaneSettings
from py_authz.core.exceptions import AuthzError
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import Identity

from .conftest import bearer


class FakeOpenFGAClient:
    instances: list["FakeOpenFGAClient"] = []

    def __init__(self, *, api_url, store_id=None, model_id=None):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        self.latest_model: dict | None = {"id": "old-model", "type_definitions": []}
        self.aclose_called = False
        FakeOpenFGAClient.instances.append(self)

    @classmethod
    def for_tenant(cls, *, api_url, store_id=None, model_id=None, **kwargs):
        return cls(api_url=api_url, store_id=store_id, model_id=model_id)

    async def get_latest_model(self):
        return self.latest_model

    async def aclose(self):
        self.aclose_called = True


class FakeModelSync:
    instances: list["FakeModelSync"] = []
    #: Class-level so a test can flip it before the route constructs its
    #: own instance (the route builds this internally — there's no
    #: per-request injection point to hand a pre-configured one through).
    changed_result: bool = True

    def __init__(self, fga_client, model_factory=None):
        self.fga_client = fga_client
        self.model_factory = model_factory
        self.sync_calls: list[bool] = []
        self.last_sync_changed: bool | None = None
        FakeModelSync.instances.append(self)

    async def sync(self, force=False):
        self.sync_calls.append(force)
        self.last_sync_changed = FakeModelSync.changed_result
        return "new-model-id"


class FakeModelVersionStore:
    def __init__(self):
        self.recorded: list[dict] = []
        self.versions: dict[int, ModelVersion] = {}
        self._counter = 0

    async def record(self, *, tenant_id, model_id, schema_json, change_summary, created_by):
        self._counter += 1
        version = ModelVersion(
            id=self._counter,
            tenant_id=tenant_id,
            model_id=model_id,
            schema_json=schema_json,
            change_summary=change_summary,
            created_by=created_by,
            created_at=datetime(2026, 1, 1),
        )
        self.versions[version.id] = version
        self.recorded.append(
            {
                "tenant_id": tenant_id,
                "model_id": model_id,
                "change_summary": change_summary,
                "created_by": created_by,
            }
        )
        return version

    async def history(self, tenant_id, *, limit=50, offset=0):
        return [v for v in self.versions.values() if v.tenant_id == tenant_id]

    async def get(self, version_id):
        return self.versions.get(version_id)


@pytest.fixture(autouse=True)
def patch_openfga_and_sync(monkeypatch):
    FakeOpenFGAClient.instances = []
    FakeModelSync.instances = []
    FakeModelSync.changed_result = True
    monkeypatch.setattr(models_routes, "OpenFGAClient", FakeOpenFGAClient)
    monkeypatch.setattr(models_routes, "ModelSync", FakeModelSync)


@pytest.fixture
def tenant_store():
    return InMemoryTenantStore()


@pytest.fixture
def model_version_store():
    return FakeModelVersionStore()


@pytest.fixture
def app(
    rbac_authz, oidc_validator, operator_store, bootstrapper, tenant_store, model_version_store
):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(models_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.tenant_store = tenant_store
    fastapi_app.state.model_version_store = model_version_store
    fastapi_app.state.settings = ControlPlaneSettings(
        fga_api_url="http://fake-openfga",
        rbac_fga_api_url="http://fake-openfga",
        rbac_fga_store_id="rbac-store",
    )

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_get_current_model_requires_system_viewer(client, rbac_authz):
    resp = client.get("/api/v1/models", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "viewer", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/models", headers=bearer())
    assert resp.status_code == 200
    assert "type_definitions" in resp.json()


@pytest.mark.asyncio
async def test_sync_requires_tenant_admin(client, rbac_authz, tenant_store):
    await tenant_store.set("acme", "store-for-acme")

    resp = client.post("/api/v1/models/sync", headers=bearer(), params={"tenant_id": "acme"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_sync_unknown_tenant_is_404(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="never-provisioned"))

    resp = client.post(
        "/api/v1/models/sync", headers=bearer(), params={"tenant_id": "never-provisioned"}
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_dry_run_reports_would_change_without_recording_a_version(
    client, rbac_authz, tenant_store, model_version_store
):
    await tenant_store.set("acme", "store-for-acme")
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/models/sync",
        headers=bearer(),
        params={"tenant_id": "acme", "dry_run": "true"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["dry_run"] is True
    assert body["would_change"] is True  # FakeOpenFGAClient's stub model != the real one
    assert model_version_store.recorded == []
    # Dry run closes the client it opened, and never touches ModelSync.
    assert FakeOpenFGAClient.instances[-1].aclose_called is True
    assert FakeModelSync.instances == []


@pytest.mark.asyncio
async def test_real_sync_records_a_version_when_changed(
    client, rbac_authz, tenant_store, model_version_store
):
    await tenant_store.set("acme", "store-for-acme")
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post("/api/v1/models/sync", headers=bearer(), params={"tenant_id": "acme"})

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"tenant_id": "acme", "model_id": "new-model-id", "changed": True}
    assert len(model_version_store.recorded) == 1
    assert model_version_store.recorded[0]["created_by"] == "user:alice"
    assert FakeOpenFGAClient.instances[-1].aclose_called is True


@pytest.mark.asyncio
async def test_real_sync_does_not_record_a_version_when_unchanged(
    client, rbac_authz, tenant_store, model_version_store
):
    await tenant_store.set("acme", "store-for-acme")
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))
    FakeModelSync.changed_result = False

    resp = client.post("/api/v1/models/sync", headers=bearer(), params={"tenant_id": "acme"})

    assert resp.status_code == 200
    assert resp.json()["changed"] is False
    assert model_version_store.recorded == []


@pytest.mark.asyncio
async def test_model_history_requires_tenant_auditor(client, rbac_authz, model_version_store):
    await model_version_store.record(
        tenant_id="acme",
        model_id="m1",
        schema_json={},
        change_summary="initial",
        created_by="user:alice",
    )

    resp = client.get("/api/v1/tenants/acme/models/history", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))
    resp = client.get("/api/v1/tenants/acme/models/history", headers=bearer())
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["change_summary"] == "initial"


@pytest.mark.asyncio
async def test_rollback_requires_a_version_recorded_for_that_tenant(
    client, rbac_authz, tenant_store, model_version_store
):
    await tenant_store.set("acme", "store-for-acme")
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))
    # Recorded under a different tenant.
    await model_version_store.record(
        tenant_id="other-corp",
        model_id="m1",
        schema_json={},
        change_summary="initial",
        created_by="user:alice",
    )

    resp = client.post(
        "/api/v1/tenants/acme/models/rollback", headers=bearer(), json={"version_id": 1}
    )

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_rollback_unknown_tenant_is_404(client, rbac_authz, model_version_store):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="never-provisioned"))
    await model_version_store.record(
        tenant_id="never-provisioned",
        model_id="m1",
        schema_json={"id": "old"},
        change_summary="initial",
        created_by="user:alice",
    )

    resp = client.post(
        "/api/v1/tenants/never-provisioned/models/rollback",
        headers=bearer(),
        json={"version_id": 1},
    )

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_rollback_forces_a_sync_to_the_old_schema_and_records_a_new_version(
    client, rbac_authz, tenant_store, model_version_store
):
    await tenant_store.set("acme", "store-for-acme")
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))
    await model_version_store.record(
        tenant_id="acme",
        model_id="m1",
        schema_json={"id": "old-schema"},
        change_summary="initial",
        created_by="user:alice",
    )

    resp = client.post(
        "/api/v1/tenants/acme/models/rollback", headers=bearer(), json={"version_id": 1}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body == {
        "tenant_id": "acme",
        "model_id": "new-model-id",
        "rolled_back_to_version": 1,
    }
    # force=True — a rollback always re-syncs, even if the diff looks like
    # a no-op (mirrors ModelSync.sync's own `force` contract).
    assert FakeModelSync.instances[-1].sync_calls == [True]
    assert FakeModelSync.instances[-1].model_factory() == {"id": "old-schema"}
    assert len(model_version_store.recorded) == 2
    assert "rolled back to version 1" in model_version_store.recorded[-1]["change_summary"]

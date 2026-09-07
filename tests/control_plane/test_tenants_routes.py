"""Tests for py_authz.control_plane.routes.tenants (CP-4): tenant CRUD,
and the three-way role split — create/list is system-wide
(`system#operator`+), get/provision is that tenant's own
`tenant#auditor`/`tenant#admin`, and deprovision accepts either that
tenant's `tenant#admin` or `system#owner`."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.routes import tenants as tenants_routes
from py_authz.core.exceptions import AuthzError
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import Identity

from .conftest import bearer


class FakeTenantManager:
    def __init__(self):
        self.provisioned: list[str] = []
        self.deprovisioned: list[str] = []
        self._store_ids: dict[str, str] = {}

    async def provision(self, tenant_id):
        self.provisioned.append(tenant_id)
        store_id = self._store_ids.setdefault(tenant_id, f"store-for-{tenant_id}")
        return store_id

    async def deprovision(self, tenant_id, *, model_registry=None):
        self.deprovisioned.append(tenant_id)


@pytest.fixture
def tenant_store():
    return InMemoryTenantStore()


@pytest.fixture
def tenant_manager():
    return FakeTenantManager()


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper, tenant_store, tenant_manager):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(tenants_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.tenant_store = tenant_store
    fastapi_app.state.tenant_manager = tenant_manager
    fastapi_app.state.model_registry = None

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_create_requires_system_operator(client, rbac_authz, tenant_manager):
    resp = client.post("/api/v1/tenants", headers=bearer(), json={"tenant_id": "acme"})
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))
    resp = client.post("/api/v1/tenants", headers=bearer(), json={"tenant_id": "acme"})
    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": "acme", "store_id": "store-for-acme"}
    assert tenant_manager.provisioned == ["acme"]


@pytest.mark.asyncio
async def test_list_requires_system_auditor(client, rbac_authz, tenant_store):
    await tenant_store.set("acme", "store-for-acme")

    resp = client.get("/api/v1/tenants", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/tenants", headers=bearer())
    assert resp.status_code == 200
    assert resp.json() == {"items": ["acme"]}


@pytest.mark.asyncio
async def test_get_tenant_requires_that_tenants_own_auditor_role(client, rbac_authz, tenant_store):
    await tenant_store.set("acme", "store-for-acme")

    # A system-wide role does not satisfy the per-tenant check.
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/tenants/acme", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))
    resp = client.get("/api/v1/tenants/acme", headers=bearer())
    assert resp.status_code == 200
    assert resp.json() == {"tenant_id": "acme", "store_id": "store-for-acme"}


@pytest.mark.asyncio
async def test_get_unknown_tenant_is_404(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="never-provisioned"))

    resp = client.get("/api/v1/tenants/never-provisioned", headers=bearer())

    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_provision_route_requires_tenant_admin(client, rbac_authz, tenant_manager):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post("/api/v1/tenants/acme/provision", headers=bearer())

    assert resp.status_code == 200
    assert tenant_manager.provisioned == ["acme"]


@pytest.mark.asyncio
async def test_deprovision_via_tenant_admin(client, rbac_authz, tenant_manager):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.delete("/api/v1/tenants/acme", headers=bearer())

    assert resp.status_code == 200
    assert resp.json() == {"status": "deprovisioned", "tenant_id": "acme"}
    assert tenant_manager.deprovisioned == ["acme"]


@pytest.mark.asyncio
async def test_deprovision_via_system_owner(client, rbac_authz, tenant_manager):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.delete("/api/v1/tenants/acme", headers=bearer())

    assert resp.status_code == 200
    assert tenant_manager.deprovisioned == ["acme"]


@pytest.mark.asyncio
async def test_deprovision_denied_without_either(client, rbac_authz, tenant_manager):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.delete("/api/v1/tenants/acme", headers=bearer())

    assert resp.status_code == 403
    assert tenant_manager.deprovisioned == []

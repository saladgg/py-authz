"""Tests for py_authz.control_plane.routes.tuples (CP-8): the tuple
read API (relationship-explorer building block) and manual grant/revoke,
`tenant#auditor`/`tenant#admin`-gated — reusing `Authz.grant`/`revoke`
unchanged, with the mandatory `reason` field and the acting operator
passed through as `actor`."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import Tenant
from py_authz.control_plane.routes import tuples as tuples_routes
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity

from .conftest import bearer


class FakeTenantAuthz:
    def __init__(self):
        self.read_calls: list[dict] = []
        self.granted: list[dict] = []
        self.revoked: list[dict] = []

    async def read_tuples(self, **kwargs):
        self.read_calls.append(kwargs)
        return {"tuples": [{"user": "user:bob", "relation": "viewer", "object": "document:1"}]}

    async def grant(self, identity, relation, resource, *, reason=None, actor=None):
        self.granted.append(
            {
                "user": identity.id,
                "relation": relation,
                "object": resource.to_fga_object(),
                "reason": reason,
                "actor": actor.id if actor else None,
            }
        )

    async def revoke(self, identity, relation, resource, *, reason=None, actor=None):
        self.revoked.append(
            {
                "user": identity.id,
                "relation": relation,
                "object": resource.to_fga_object(),
                "reason": reason,
                "actor": actor.id if actor else None,
            }
        )


class FakeMultiTenantAuthz:
    def __init__(self):
        self.tenants: dict[str, FakeTenantAuthz] = {}

    async def for_tenant(self, tenant_id):
        return self.tenants.setdefault(tenant_id, FakeTenantAuthz())


@pytest.fixture
def multi_tenant_authz():
    return FakeMultiTenantAuthz()


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper, multi_tenant_authz):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(tuples_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.multi_tenant_authz = multi_tenant_authz

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_list_tuples_requires_tenant_auditor(client, rbac_authz, multi_tenant_authz):
    resp = client.get("/api/v1/tenants/acme/tuples", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))
    resp = client.get(
        "/api/v1/tenants/acme/tuples",
        headers=bearer(),
        params={"user": "user:bob", "relation": "viewer"},
    )
    assert resp.status_code == 200
    assert resp.json()["tuples"][0]["user"] == "user:bob"
    assert multi_tenant_authz.tenants["acme"].read_calls == [
        {
            "user": "user:bob",
            "relation": "viewer",
            "object": None,
            "page_size": None,
            "continuation_token": None,
        }
    ]


@pytest.mark.asyncio
async def test_grant_requires_tenant_admin_not_auditor(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/tenants/acme/grants",
        headers=bearer(),
        json={
            "user": "user:bob",
            "relation": "viewer",
            "object": {"type": "document", "id": "roadmap"},
            "reason": "onboarding",
        },
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_grant_passes_reason_and_acting_operator_through(
    client, rbac_authz, multi_tenant_authz
):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/tenants/acme/grants",
        headers=bearer(),
        json={
            "user": "user:bob",
            "relation": "viewer",
            "object": {"type": "document", "id": "roadmap"},
            "reason": "onboarding",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "granted",
        "user": "user:bob",
        "relation": "viewer",
        "object": "document:roadmap",
    }
    assert multi_tenant_authz.tenants["acme"].granted == [
        {
            "user": "user:bob",
            "relation": "viewer",
            "object": "document:roadmap",
            "reason": "onboarding",
            "actor": "user:alice",
        }
    ]


@pytest.mark.asyncio
async def test_grant_requires_a_nonempty_reason(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/tenants/acme/grants",
        headers=bearer(),
        json={
            "user": "user:bob",
            "relation": "viewer",
            "object": {"type": "document", "id": "roadmap"},
            "reason": "",
        },
    )

    assert resp.status_code == 422  # pydantic validation error, min_length=1


@pytest.mark.asyncio
async def test_revoke_requires_tenant_admin(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/tenants/acme/revokes",
        headers=bearer(),
        json={
            "user": "user:bob",
            "relation": "viewer",
            "object": {"type": "document", "id": "roadmap"},
            "reason": "offboarding",
        },
    )

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoke_passes_reason_and_acting_operator_through(
    client, rbac_authz, multi_tenant_authz
):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/tenants/acme/revokes",
        headers=bearer(),
        json={
            "user": "user:bob",
            "relation": "viewer",
            "object": {"type": "document", "id": "roadmap"},
            "reason": "offboarding",
        },
    )

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "revoked",
        "user": "user:bob",
        "relation": "viewer",
        "object": "document:roadmap",
    }
    assert multi_tenant_authz.tenants["acme"].revoked == [
        {
            "user": "user:bob",
            "relation": "viewer",
            "object": "document:roadmap",
            "reason": "offboarding",
            "actor": "user:alice",
        }
    ]

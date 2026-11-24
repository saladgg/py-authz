"""Tests for py_authz.control_plane.routes.operators — role assignment
against the dogfooded RBAC store (backend for CP-13's Operators & Roles
screen)."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.api import Authz
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import RBAC_MODELS, SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.routes import operators as operators_routes
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient


class FakeOperatorStore:
    def __init__(self, operators=None):
        self._operators = operators or []

    async def list(self):
        return self._operators


class FakeServiceAccount:
    def __init__(self, id, revoked=False):
        self.id = id
        self.is_revoked = revoked


class FakeServiceAccountStore:
    def __init__(self, accounts=None):
        self._accounts = {a.id: a for a in (accounts or [])}

    async def get(self, account_id):
        return self._accounts.get(account_id)


class Operator:
    def __init__(self, id, subject, email, created_at):
        self.id = id
        self.subject = subject
        self.email = email
        self.created_at = created_at


@pytest.fixture
def rbac_authz():
    reg = ResourceModelRegistry()
    # Strict mode + the full RBAC model (incl. the `service_account`
    # subject type): reject what a real OpenFGA rejects (ARCH3-9).
    for model in RBAC_MODELS:
        reg.register(model)
    client = InMemoryFGAClient(model_registry=reg, strict=True)
    return Authz(AuthzEngine(fga_client=client))


@pytest.fixture
def app(rbac_authz):
    from datetime import datetime

    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(operators_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.service_account_store = FakeServiceAccountStore(
        [FakeServiceAccount("sa_ci"), FakeServiceAccount("sa_gone", revoked=True)]
    )
    fastapi_app.state.operator_store = FakeOperatorStore(
        [Operator("1", "alice", "alice@example.com", datetime(2026, 1, 1))]
    )

    # Bypass real OIDC — a lightweight dependency override standing in
    # for `get_current_principal`, matching whichever identity the test
    # sets via `current_identity`.
    from py_authz.control_plane.auth import CurrentPrincipal, get_current_principal

    async def _fake_principal():
        return CurrentPrincipal(identity=Identity(id=fastapi_app.state.caller_id), kind="operator")

    fastapi_app.dependency_overrides[get_current_principal] = _fake_principal
    fastapi_app.state.caller_id = "user:alice"

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_list_operators_requires_system_auditor(client, app, rbac_authz):
    resp = client.get("/api/v1/operators")
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/operators")
    assert resp.status_code == 200
    assert resp.json()["items"][0]["subject"] == "alice"


@pytest.mark.asyncio
async def test_granting_a_system_role_requires_system_owner(client, rbac_authz):
    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "system", "role": "operator"},
    )
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))
    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "system", "role": "operator"},
    )
    assert resp.status_code == 200

    system_resource_check = await rbac_authz.can(
        "operator", Identity(id="user:bob"), System(id=SYSTEM_OBJECT_ID).to_resource()
    )
    assert system_resource_check is True


@pytest.mark.asyncio
async def test_system_admin_cannot_grant_a_system_role(client, rbac_authz):
    """Only system#owner manages system-scoped roles — admin isn't enough."""
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "system", "role": "operator"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_granting_a_tenant_role_accepts_tenant_admin(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "tenant_id": "acme", "role": "auditor"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_granting_a_tenant_role_also_accepts_system_owner(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "tenant_id": "acme", "role": "auditor"},
    )
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_granting_a_tenant_role_rejects_unrelated_operator(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="other-corp"))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "tenant_id": "acme", "role": "auditor"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_revoke_role(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))
    await rbac_authz.grant(Identity(id="user:bob"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.request(
        "DELETE",
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "system", "role": "operator"},
    )
    assert resp.status_code == 200

    assert (
        await rbac_authz.can(
            "operator", Identity(id="user:bob"), System(id=SYSTEM_OBJECT_ID).to_resource()
        )
        is False
    )


@pytest.mark.asyncio
async def test_list_roles_for_system_scope(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    await rbac_authz.grant(Identity(id="user:bob"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/operators/roles", params={"scope": "system"})
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert {"subject": "user:bob", "role": "operator"} in items


@pytest.mark.asyncio
async def test_list_roles_for_tenant_scope_via_tenant_auditor(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))
    await rbac_authz.grant(Identity(id="user:bob"), "admin", Tenant(id="acme"))

    resp = client.get("/api/v1/operators/roles", params={"scope": "tenant", "tenant_id": "acme"})

    assert resp.status_code == 200
    assert {"subject": "user:bob", "role": "admin"} in resp.json()["items"]


@pytest.mark.asyncio
async def test_list_roles_for_tenant_scope_via_system_owner(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))
    await rbac_authz.grant(Identity(id="user:bob"), "admin", Tenant(id="acme"))

    resp = client.get("/api/v1/operators/roles", params={"scope": "tenant", "tenant_id": "acme"})

    assert resp.status_code == 200
    assert {"subject": "user:bob", "role": "admin"} in resp.json()["items"]


@pytest.mark.asyncio
async def test_list_roles_for_tenant_scope_denied_without_either(client, rbac_authz):
    # A system-scoped auditor role does not satisfy a tenant-scoped
    # roles listing — same independent-scopes rule as elsewhere.
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/operators/roles", params={"scope": "tenant", "tenant_id": "acme"})

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_grant_rejects_unknown_role(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "system", "role": "superadmin"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_grant_tenant_role_without_tenant_id_is_400(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "role": "auditor"},
    )
    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_grant_rejects_unknown_scope(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "planet", "role": "auditor"},
    )

    assert resp.status_code == 400


# -------------------------------------------------------------------
# SEC3-4: tenant operators may only manage roles strictly below their own
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_admin_cannot_promote_anyone_to_tenant_owner(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    for subject in ("alice", "bob"):
        resp = client.post(
            "/api/v1/operators/roles",
            json={"subject": subject, "scope": "tenant", "tenant_id": "acme", "role": "owner"},
        )
        assert resp.status_code == 403


@pytest.mark.asyncio
async def test_tenant_admin_cannot_grant_a_peer_admin_role(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "tenant_id": "acme", "role": "admin"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_tenant_admin_cannot_revoke_a_tenant_owner(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))
    await rbac_authz.grant(Identity(id="user:carol"), "owner", Tenant(id="acme"))

    resp = client.request(
        "DELETE",
        "/api/v1/operators/roles",
        json={"subject": "carol", "scope": "tenant", "tenant_id": "acme", "role": "owner"},
    )

    assert resp.status_code == 403
    assert await rbac_authz.can("owner", Identity(id="user:carol"), Tenant(id="acme").to_resource())


@pytest.mark.asyncio
async def test_tenant_owner_may_manage_any_tenant_role(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", Tenant(id="acme"))

    resp = client.post(
        "/api/v1/operators/roles",
        json={"subject": "bob", "scope": "tenant", "tenant_id": "acme", "role": "owner"},
    )
    assert resp.status_code == 200


# -------------------------------------------------------------------
# SEC3-3: roles can be granted to service accounts (by id)
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_system_owner_can_grant_a_role_to_a_service_account(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/operators/roles",
        json={
            "subject": "sa_ci",
            "subject_kind": "service_account",
            "scope": "tenant",
            "tenant_id": "acme",
            "role": "operator",
        },
    )

    assert resp.status_code == 200
    assert await rbac_authz.can(
        "operator", Identity(id="service_account:sa_ci"), Tenant(id="acme").to_resource()
    )


@pytest.mark.asyncio
async def test_granting_a_role_to_an_unknown_or_revoked_service_account_is_400(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    for subject in ("sa_missing", "sa_gone"):
        resp = client.post(
            "/api/v1/operators/roles",
            json={
                "subject": subject,
                "subject_kind": "service_account",
                "scope": "system",
                "role": "viewer",
            },
        )
        assert resp.status_code == 400

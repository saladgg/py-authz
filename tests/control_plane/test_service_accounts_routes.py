"""Tests for py_authz.control_plane.routes.service_accounts (CP-3):
create/list/revoke/rotate, `system#admin`-gated (auditor for the list
route), and the `secret`/`secret_hash` serialization contract (a plaintext
secret only ever appears in a create/rotate response, never in `list`)."""

from datetime import datetime

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import service_accounts as sa_routes
from py_authz.control_plane.service_accounts import ServiceAccount
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity

from .conftest import bearer


class FakeServiceAccountStore:
    def __init__(self):
        self.accounts: dict[str, ServiceAccount] = {}
        self.created_kwargs: list[dict] = []
        self.revoked: list[str] = []
        self._counter = 0

    async def create(self, *, name, description, scopes, created_by):
        self._counter += 1
        account_id = f"sa_{self._counter}"
        self.created_kwargs.append(
            {"name": name, "description": description, "scopes": scopes, "created_by": created_by}
        )
        account = ServiceAccount(
            id=account_id,
            name=name,
            description=description,
            scopes=scopes,
            secret_hash="unused-in-fake",  # noqa: S106 — placeholder, never verified in this fake
            created_by=created_by,
            created_at=datetime(2026, 1, 1),
            last_used_at=None,
            revoked_at=None,
        )
        self.accounts[account_id] = account
        return account, f"pasa_{account_id}.secret"

    async def list(self):
        return list(self.accounts.values())

    async def revoke(self, account_id):
        self.revoked.append(account_id)

    async def rotate(self, account_id):
        account = self.accounts[account_id]
        return account, f"pasa_{account_id}.new-secret"


@pytest.fixture
def service_account_store():
    return FakeServiceAccountStore()


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper, service_account_store):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(sa_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.service_account_store = service_account_store

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_create_requires_system_admin(client, rbac_authz):
    resp = client.post("/api/v1/service-accounts", headers=bearer(), json={"name": "ci-bot"})
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))
    resp = client.post("/api/v1/service-accounts", headers=bearer(), json={"name": "ci-bot"})
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_create_returns_the_secret_exactly_once(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/service-accounts",
        headers=bearer(),
        json={"name": "ci-bot", "description": "runs CI", "scopes": ["models:sync"]},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["secret"] == "pasa_sa_1.secret"  # noqa: S105 — fixture value, not a real credential
    assert body["name"] == "ci-bot"
    assert body["description"] == "runs CI"
    assert body["scopes"] == ["models:sync"]
    assert "secret_hash" not in body
    assert app.state.service_account_store.created_kwargs[0]["created_by"] == "user:alice"


@pytest.mark.asyncio
async def test_list_requires_system_auditor_not_admin(client, rbac_authz, service_account_store):
    await service_account_store.create(
        name="ci-bot", description=None, scopes=[], created_by="user:alice"
    )

    resp = client.get("/api/v1/service-accounts", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/service-accounts", headers=bearer())
    assert resp.status_code == 200
    items = resp.json()["items"]
    assert len(items) == 1
    assert "secret" not in items[0]
    assert "secret_hash" not in items[0]


@pytest.mark.asyncio
async def test_revoke_requires_system_admin(app, client, rbac_authz, service_account_store):
    await service_account_store.create(
        name="ci-bot", description=None, scopes=[], created_by="user:alice"
    )
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.delete("/api/v1/service-accounts/sa_1", headers=bearer())

    assert resp.status_code == 200
    assert resp.json() == {"status": "revoked", "id": "sa_1"}
    assert app.state.service_account_store.revoked == ["sa_1"]


@pytest.mark.asyncio
async def test_rotate_returns_a_new_secret(client, rbac_authz, service_account_store):
    await service_account_store.create(
        name="ci-bot", description=None, scopes=["models:sync"], created_by="user:alice"
    )
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/service-accounts/sa_1/rotate", headers=bearer())

    assert resp.status_code == 200
    body = resp.json()
    assert body["secret"] == "pasa_sa_1.new-secret"  # noqa: S105 — fixture value
    assert body["id"] == "sa_1"

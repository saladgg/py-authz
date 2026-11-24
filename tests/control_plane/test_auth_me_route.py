"""Tests for py_authz.control_plane.routes.auth_routes — the real
`GET /auth/me` route (CP-2). `test_auth.py` already exercises
`get_current_principal`/`effective_system_role` at the dependency level
against custom test routes; this file drives the actual router, closing
the coverage gap on `effective_system_role`'s loop-through-`ROLE_CHAIN`
body and its "holds nothing" fallback, which nothing else calls this
router to exercise."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rate_limit import InMemoryRateLimiter
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import auth_routes
from py_authz.control_plane.security import generate_secret, hash_secret
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity

from .conftest import bearer


class FakeServiceAccountRecord:
    def __init__(self, id, name, scopes, secret_hash):
        self.id = id
        self.name = name
        self.scopes = scopes
        self.secret_hash = secret_hash
        self.is_revoked = False


class FakeServiceAccountStore:
    def __init__(self):
        self.accounts: dict[str, FakeServiceAccountRecord] = {}

    async def get(self, account_id):
        return self.accounts.get(account_id)

    async def touch_last_used(self, account_id):
        pass


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(auth_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.service_account_store = FakeServiceAccountStore()
    fastapi_app.state.service_account_rate_limiter = InMemoryRateLimiter()

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_operator_with_no_system_role_reports_none(client):
    resp = client.get("/api/v1/auth/me", headers=bearer())

    assert resp.status_code == 200
    body = resp.json()
    assert body == {"id": "user:alice", "kind": "operator", "scopes": None, "system_role": None}


@pytest.mark.asyncio
async def test_operator_reports_their_highest_system_role(client, rbac_authz):
    """`owner` implies `operator`/`auditor`/`viewer` via the union chain
    — `effective_system_role` must report the highest one, not just any
    one that happens to pass."""
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/auth/me", headers=bearer())

    assert resp.status_code == 200
    assert resp.json()["system_role"] == "owner"


@pytest.mark.asyncio
async def test_operator_reports_a_lower_role_when_that_is_all_they_hold(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "viewer", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/api/v1/auth/me", headers=bearer())

    assert resp.status_code == 200
    assert resp.json()["system_role"] == "viewer"


def test_service_account_reports_scopes_and_no_system_role(app, client):
    """A service account's `system_role` is always `None` — that lookup
    only applies to operators (see `get_me`'s docstring); its scopes are
    reported instead, unlike an operator's (always `None`)."""
    secret = generate_secret("sa_1")
    app.state.service_account_store.accounts["sa_1"] = FakeServiceAccountRecord(
        id="sa_1", name="ci-bot", scopes=["models:write"], secret_hash=hash_secret(secret)
    )

    resp = client.get("/api/v1/auth/me", headers=bearer(secret))

    assert resp.status_code == 200
    assert resp.json() == {
        "id": "service_account:sa_1",
        "kind": "service_account",
        "scopes": ["models:write"],
        "system_role": None,
    }

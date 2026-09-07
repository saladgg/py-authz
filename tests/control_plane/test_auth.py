"""
Tests for py_authz.control_plane.auth — the operator/service-account
authentication dispatch and the `require_system_role`/`require_tenant_role`
FastAPI dependency factories (CP-2, CP-3).

Builds a small standalone FastAPI app (not `create_app()` — no real
Postgres/OpenFGA/Redis needed) with `app.state` populated by fakes, and
drives it with `TestClient` so the dependencies run exactly as they would
in the real app.
"""

import pytest
from fastapi import Depends, FastAPI
from starlette.testclient import TestClient

from py_authz.api import Authz
from py_authz.control_plane.auth import (
    get_current_principal,
    require_system_or_tenant_role_from_query,
    require_system_role,
    require_tenant_admin_or_system_owner,
    require_tenant_role,
    require_tenant_role_from_query,
)
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rate_limit import InMemoryRateLimiter
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.security import generate_secret, hash_secret
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import Identity
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient


class FakeOIDCValidator:
    def __init__(self, tokens: dict[str, dict]):
        self.tokens = tokens

    async def validate(self, token: str) -> dict:
        from py_authz.core.exceptions import AuthenticationError

        if token not in self.tokens:
            raise AuthenticationError("invalid token")
        return self.tokens[token]

    def to_identity(self, payload: dict) -> Identity:
        return Identity(id=f"user:{payload['sub']}", attributes=payload)


class FakeOperatorStore:
    def __init__(self):
        self.logins: list[str] = []

    async def record_login(self, *, subject, email):
        self.logins.append(subject)


class FakeBootstrapper:
    def __init__(self):
        self.calls: list[Identity] = []

    async def maybe_bootstrap(self, identity: Identity) -> None:
        self.calls.append(identity)


class FakeServiceAccountRecord:
    def __init__(self, id, name, scopes, secret_hash, revoked=False):
        self.id = id
        self.name = name
        self.scopes = scopes
        self.secret_hash = secret_hash
        self.revoked_at = "now" if revoked else None

    @property
    def is_revoked(self):
        return self.revoked_at is not None


class FakeServiceAccountStore:
    def __init__(self):
        self.accounts: dict[str, FakeServiceAccountRecord] = {}
        self.touched: list[str] = []

    async def get(self, account_id):
        return self.accounts.get(account_id)

    async def touch_last_used(self, account_id):
        self.touched.append(account_id)


@pytest.fixture
def rbac_authz():
    reg = ResourceModelRegistry()
    reg.register(System)
    reg.register(Tenant)
    client = InMemoryFGAClient(model_registry=reg)
    return Authz(AuthzEngine(fga_client=client))


@pytest.fixture
def app(rbac_authz):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = FakeOIDCValidator(
        {"good-token": {"sub": "alice", "email": "alice@example.com"}}
    )
    fastapi_app.state.operator_store = FakeOperatorStore()
    fastapi_app.state.bootstrapper = FakeBootstrapper()
    fastapi_app.state.service_account_store = FakeServiceAccountStore()
    fastapi_app.state.service_account_rate_limiter = InMemoryRateLimiter()

    @fastapi_app.get("/system", dependencies=[Depends(require_system_role("operator"))])
    async def system_route():
        return {"ok": True}

    @fastapi_app.get(
        "/system-scoped",
        dependencies=[
            Depends(require_system_role("operator", service_account_scope="models:sync"))
        ],
    )
    async def system_scoped_route():
        return {"ok": True}

    @fastapi_app.get("/tenants/{tenant_id}", dependencies=[Depends(require_tenant_role("auditor"))])
    async def tenant_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.delete(
        "/tenants/{tenant_id}",
        dependencies=[Depends(require_tenant_admin_or_system_owner())],
    )
    async def delete_tenant_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.get(
        "/models-sync", dependencies=[Depends(require_tenant_role_from_query("admin"))]
    )
    async def models_sync_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.get(
        "/audit-logs",
        dependencies=[Depends(require_system_or_tenant_role_from_query("auditor"))],
    )
    async def audit_logs_route(tenant_id: str | None = None):
        return {"ok": True}

    @fastapi_app.get("/me")
    async def me(principal=Depends(get_current_principal)):
        return {
            "id": principal.identity.id,
            "kind": principal.kind,
            "scopes": list(principal.scopes),
        }

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


# -------------------------------------------------------------------
# Missing/invalid credentials
# -------------------------------------------------------------------


def test_missing_authorization_header_is_401(client):
    resp = client.get("/system")
    assert resp.status_code == 401


def test_malformed_authorization_header_is_401(client):
    resp = client.get("/system", headers={"Authorization": "NotBearer xyz"})
    assert resp.status_code == 401


def test_invalid_oidc_token_is_401(client):
    resp = client.get("/system", headers=_bearer("garbage-token"))
    assert resp.status_code == 401


# -------------------------------------------------------------------
# Operator auth: records login + runs break-glass bootstrap
# -------------------------------------------------------------------


def test_valid_operator_token_records_login_and_runs_bootstrap(client, app):
    client.get("/me", headers=_bearer("good-token"))

    assert app.state.operator_store.logins == ["alice"]
    assert len(app.state.bootstrapper.calls) == 1
    assert app.state.bootstrapper.calls[0].id == "user:alice"


def test_me_reports_operator_identity(client):
    resp = client.get("/me", headers=_bearer("good-token"))
    assert resp.status_code == 200
    assert resp.json() == {"id": "user:alice", "kind": "operator", "scopes": []}


# -------------------------------------------------------------------
# require_system_role
# -------------------------------------------------------------------


def test_system_role_denied_without_grant(client):
    resp = client.get("/system", headers=_bearer("good-token"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_system_role_allowed_after_grant(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/system", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_higher_role_satisfies_a_lower_requirement(client, rbac_authz):
    """`owner` implies `operator` via the union chain — no separate grant
    needed."""
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/system", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_lower_role_does_not_satisfy_a_higher_requirement(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "viewer", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/system", headers=_bearer("good-token"))
    assert resp.status_code == 403


# -------------------------------------------------------------------
# require_tenant_role
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_role_is_independent_of_system_role(client, rbac_authz):
    """A `system#owner` does NOT automatically pass a `tenant#auditor`
    check — the two scopes are deliberately independent (see
    `require_tenant_role`'s docstring)."""
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/tenants/acme", headers=_bearer("good-token"))
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_tenant_role_allowed_after_explicit_grant(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))

    resp = client.get("/tenants/acme", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_tenant_role_grant_on_one_tenant_does_not_leak_to_another(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))

    resp = client.get("/tenants/other-corp", headers=_bearer("good-token"))
    assert resp.status_code == 403


# -------------------------------------------------------------------
# require_tenant_admin_or_system_owner (CP-4's deprovision route)
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deprovision_allowed_via_tenant_admin(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.delete("/tenants/acme", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_deprovision_allowed_via_system_owner(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "owner", System(id=SYSTEM_OBJECT_ID))

    resp = client.delete("/tenants/acme", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_deprovision_denied_without_either(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", System(id=SYSTEM_OBJECT_ID))

    resp = client.delete("/tenants/acme", headers=_bearer("good-token"))
    assert resp.status_code == 403


# -------------------------------------------------------------------
# require_tenant_role_from_query / require_system_or_tenant_role_from_query
# -------------------------------------------------------------------


def test_tenant_role_from_query_requires_the_param(client):
    resp = client.get("/models-sync", headers=_bearer("good-token"))
    assert resp.status_code == 400  # InvalidAuthzRequest: missing tenant_id


@pytest.mark.asyncio
async def test_tenant_role_from_query_checks_that_tenant(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "admin", Tenant(id="acme"))

    resp = client.get("/models-sync", params={"tenant_id": "acme"}, headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_audit_logs_without_tenant_id_requires_system_role(client, rbac_authz):
    resp = client.get("/audit-logs", headers=_bearer("good-token"))
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/audit-logs", headers=_bearer("good-token"))
    assert resp.status_code == 200


@pytest.mark.asyncio
async def test_audit_logs_with_tenant_id_checks_that_tenant_only(client, rbac_authz):
    # System-level auditor role does NOT satisfy a tenant-scoped audit
    # query — scoping to one tenant means the tenant's own role applies.
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.get("/audit-logs", params={"tenant_id": "acme"}, headers=_bearer("good-token"))
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", Tenant(id="acme"))
    resp = client.get("/audit-logs", params={"tenant_id": "acme"}, headers=_bearer("good-token"))
    assert resp.status_code == 200


# -------------------------------------------------------------------
# Service accounts
# -------------------------------------------------------------------


def _make_service_account(app, *, account_id, name, scopes):
    secret = generate_secret(account_id)
    record = FakeServiceAccountRecord(
        id=account_id, name=name, scopes=scopes, secret_hash=hash_secret(secret)
    )
    app.state.service_account_store.accounts[account_id] = record
    return secret


def test_service_account_bad_secret_is_401(client, app):
    _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    resp = client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
    assert resp.status_code == 401


def test_service_account_unknown_id_is_401(client):
    resp = client.get("/system", headers=_bearer("pasa_sa_missing.somesecret"))
    assert resp.status_code == 401


def test_revoked_service_account_is_401(client, app):
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=["models:sync"])
    app.state.service_account_store.accounts["sa_1"].revoked_at = "now"

    resp = client.get("/system", headers=_bearer(secret))
    assert resp.status_code == 401


# -------------------------------------------------------------------
# CP-16: rate limiting on repeated failed service-account attempts
# -------------------------------------------------------------------


def test_repeated_bad_secrets_eventually_lock_out(client, app):
    _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    # Default policy: 5 failed attempts before lockout.
    for _ in range(5):
        resp = client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
        assert resp.status_code == 401

    locked_resp = client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
    assert locked_resp.status_code == 429


def test_lockout_also_blocks_the_correct_secret(client, app):
    """Once locked out, even the *correct* secret is refused until the
    lockout window elapses — the point of a lockout, not a bypass."""
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    for _ in range(5):
        client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))

    resp = client.get("/system", headers=_bearer(secret))
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_successful_auth_resets_the_failure_counter(client, app, rbac_authz):
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])
    await rbac_authz.grant(Identity(id="service:ci-bot"), "operator", System(id=SYSTEM_OBJECT_ID))

    for _ in range(3):
        client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))

    # A correct attempt before hitting the threshold resets the counter.
    ok_resp = client.get("/system", headers=_bearer(secret))
    assert ok_resp.status_code == 200

    # Three more failures afterward shouldn't be enough to lock out —
    # the earlier failures were cleared by the successful attempt.
    for _ in range(3):
        resp = client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
        assert resp.status_code == 401


def test_lockout_is_scoped_to_one_account_id(client, app):
    """A brute-force attempt against one service account must not lock
    out an unrelated one."""
    _make_service_account(app, account_id="sa_2", name="other-bot", scopes=[])
    _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    for _ in range(5):
        client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))

    resp = client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
    assert resp.status_code == 429

    # sa_2 is unaffected.
    other_resp = client.get("/system", headers=_bearer("pasa_sa_2.wrong-secret"))
    assert other_resp.status_code == 401  # not 429 — not locked out


@pytest.mark.asyncio
async def test_service_account_needs_both_scope_and_rbac_role(client, app, rbac_authz):
    """CP-3: scope check runs *before* the per-tenant/system authz.can()
    check — both must pass, neither is sufficient alone."""
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    # Has the RBAC role but not the scope.
    await rbac_authz.grant(Identity(id="service:ci-bot"), "operator", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/system-scoped", headers=_bearer(secret))
    assert resp.status_code == 403

    # Has the scope but not (yet) the RBAC role — recreate without the role.
    secret2 = _make_service_account(app, account_id="sa_2", name="ci-bot-2", scopes=["models:sync"])
    resp = client.get("/system-scoped", headers=_bearer(secret2))
    assert resp.status_code == 403

    # Both present -> allowed.
    await rbac_authz.grant(Identity(id="service:ci-bot-2"), "operator", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/system-scoped", headers=_bearer(secret2))
    assert resp.status_code == 200


def test_valid_service_account_touches_last_used(client, app):
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    client.get("/me", headers=_bearer(secret))

    assert app.state.service_account_store.touched == ["sa_1"]


def test_me_reports_service_account_identity_and_scopes(client, app):
    secret = _make_service_account(
        app, account_id="sa_1", name="ci-bot", scopes=["models:sync", "audit:read"]
    )

    resp = client.get("/me", headers=_bearer(secret))

    assert resp.status_code == 200
    body = resp.json()
    assert body["id"] == "service:ci-bot"
    assert body["kind"] == "service_account"
    assert set(body["scopes"]) == {"models:sync", "audit:read"}


# -------------------------------------------------------------------
# Unknown role name: every *_role* dependency factory validates
# min_relation against ROLE_CHAIN eagerly, at dependency-construction
# time (e.g. when the router module is imported) — not lazily on the
# first request. A typo in a route decorator should fail loudly then,
# not 403 silently forever.
# -------------------------------------------------------------------


def test_require_system_role_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_system_role("made-up")


def test_require_tenant_role_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_tenant_role("made-up")


def test_require_tenant_role_from_query_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_tenant_role_from_query("made-up")


def test_require_system_or_tenant_role_from_query_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_system_or_tenant_role_from_query("made-up")

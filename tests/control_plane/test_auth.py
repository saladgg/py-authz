"""
Tests for py_authz.control_plane.auth — the operator/service-account
authentication dispatch and the `require_system_role`/`require_tenant_role`
FastAPI dependency factories (CP-2, CP-3).

Builds a small standalone FastAPI app (not `create_app()` — no real
Postgres/OpenFGA/Redis needed) with `app.state` populated by fakes, and
drives it with `TestClient` so the dependencies run exactly as they would
in the real app.
"""

from datetime import UTC, datetime, timedelta

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
from py_authz.control_plane.rbac_model import RBAC_MODELS, SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.scopes import ANY_PRINCIPAL, Scope
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
    # Strict mode + the full RBAC model (incl. the `service_account`
    # subject type): reject what a real OpenFGA rejects (ARCH3-9).
    for model in RBAC_MODELS:
        reg.register(model)
    client = InMemoryFGAClient(model_registry=reg, strict=True)
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

    @fastapi_app.get(
        "/system", dependencies=[Depends(require_system_role("operator", scope=ANY_PRINCIPAL))]
    )
    async def system_route():
        return {"ok": True}

    @fastapi_app.get(
        "/system-scoped",
        dependencies=[Depends(require_system_role("operator", scope=Scope.MODELS_WRITE))],
    )
    async def system_scoped_route():
        return {"ok": True}

    @fastapi_app.get(
        "/tenants/{tenant_id}",
        dependencies=[Depends(require_tenant_role("auditor", scope=ANY_PRINCIPAL))],
    )
    async def tenant_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.delete(
        "/tenants/{tenant_id}",
        dependencies=[Depends(require_tenant_admin_or_system_owner(scope=ANY_PRINCIPAL))],
    )
    async def delete_tenant_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.get(
        "/models-sync",
        dependencies=[Depends(require_tenant_role_from_query("admin", scope=ANY_PRINCIPAL))],
    )
    async def models_sync_route(tenant_id: str):
        return {"ok": True}

    @fastapi_app.get(
        "/audit-logs",
        dependencies=[
            Depends(require_system_or_tenant_role_from_query("auditor", scope=ANY_PRINCIPAL))
        ],
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


def test_authenticating_runs_bootstrap_but_no_longer_records_a_login(client, app):
    """SEC3-8/REL3-19: `record_login` ran on every request, before any role
    check (a Postgres upsert per API call, and any realm user's token
    created an operators row). It now happens only in `GET /auth/me`."""
    client.get("/system", headers=_bearer("good-token"))

    assert app.state.operator_store.logins == []
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


def test_lockout_also_blocks_the_correct_secret_from_the_same_network(client, app):
    """Once locked out, even the *correct* secret is refused from that
    network until the lockout window elapses — the point of a lockout,
    not a bypass."""
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    for _ in range(5):
        client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))

    resp = client.get("/system", headers=_bearer(secret))
    assert resp.status_code == 429


@pytest.mark.asyncio
async def test_lockout_from_one_network_does_not_lock_out_the_account_elsewhere(app, rbac_authz):
    """SEC3-13: anyone who knows an SA id (auditors can list them) used to
    be able to keep it at 429 indefinitely. The lockout is now keyed on
    (account, client network): the attacker's /24 is locked, the SA's own
    network isn't."""
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])
    await rbac_authz.grant(
        Identity(id="service_account:sa_1"), "operator", System(id=SYSTEM_OBJECT_ID)
    )
    attacker = TestClient(app, client=("203.0.113.7", 40000))
    attacker_neighbour = TestClient(app, client=("203.0.113.99", 40000))
    ci = TestClient(app, client=("198.51.100.20", 40000))

    for _ in range(5):
        attacker.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))

    assert attacker.get("/system", headers=_bearer(secret)).status_code == 429
    # Same /24 shares the lockout.
    assert attacker_neighbour.get("/system", headers=_bearer(secret)).status_code == 429
    # The SA's real caller is unaffected.
    assert ci.get("/system", headers=_bearer(secret)).status_code == 200


def test_lockout_is_logged_once_as_an_alertable_event(client, app, caplog):
    _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    with caplog.at_level("WARNING", logger="py_authz.control_plane.auth"):
        for _ in range(5):
            client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))
        client.get("/system", headers=_bearer("pasa_sa_1.wrong-secret"))  # refused: 429

    lockouts = [r for r in caplog.records if "service_account_lockout" in r.getMessage()]
    assert len(lockouts) == 1
    assert '"service_account_id": "sa_1"' in lockouts[0].getMessage()


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("203.0.113.7", "203.0.113.0/24"),
        ("2001:db8:1:2:3:4:5:6", "2001:db8:1:2::/64"),
        ("testclient", "unknown"),
        ("", "unknown"),
    ],
)
def test_client_network(host, expected):
    from types import SimpleNamespace

    from py_authz.control_plane.auth import client_network

    request = SimpleNamespace(client=SimpleNamespace(host=host) if host else None)
    assert client_network(request) == expected


@pytest.mark.asyncio
async def test_successful_auth_resets_the_failure_counter(client, app, rbac_authz):
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])
    await rbac_authz.grant(
        Identity(id="service_account:sa_1"), "operator", System(id=SYSTEM_OBJECT_ID)
    )

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
    await rbac_authz.grant(
        Identity(id="service_account:sa_1"), "operator", System(id=SYSTEM_OBJECT_ID)
    )
    resp = client.get("/system-scoped", headers=_bearer(secret))
    assert resp.status_code == 403

    # Has the scope but not (yet) the RBAC role — recreate without the role.
    secret2 = _make_service_account(
        app, account_id="sa_2", name="ci-bot-2", scopes=["models:write"]
    )
    resp = client.get("/system-scoped", headers=_bearer(secret2))
    assert resp.status_code == 403

    # Both present -> allowed.
    await rbac_authz.grant(
        Identity(id="service_account:sa_2"), "operator", System(id=SYSTEM_OBJECT_ID)
    )
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
    assert body["id"] == "service_account:sa_1"
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
        require_system_role("made-up", scope=ANY_PRINCIPAL)


def test_require_tenant_role_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_tenant_role("made-up", scope=ANY_PRINCIPAL)


def test_require_tenant_role_from_query_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_tenant_role_from_query("made-up", scope=ANY_PRINCIPAL)


def test_require_system_or_tenant_role_from_query_rejects_unknown_role():
    with pytest.raises(ValueError, match="Unknown role 'made-up'"):
        require_system_or_tenant_role_from_query("made-up", scope=ANY_PRINCIPAL)


def test_dependency_factories_reject_an_unknown_scope():
    """SEC3-1: a typo'd scope on a route fails at definition time, not as
    a silently unsatisfiable (or silently skipped) check at request time."""
    with pytest.raises(ValueError):
        require_system_role("viewer", scope="models:sycn")


def test_dependency_factories_require_a_scope():
    """SEC3-1: `scope` has no default — a route can't forget to declare
    one and silently let every service account through."""
    with pytest.raises(TypeError):
        require_system_role("viewer")  # type: ignore[call-arg]


@pytest.mark.asyncio
async def test_service_account_principal_is_keyed_on_id_not_name(client, app, rbac_authz):
    """SEC3-2: a role granted to one account must not carry over to a
    different account that happens to share (or later reuse) its name."""
    await rbac_authz.grant(
        Identity(id="service_account:sa_old"), "operator", System(id=SYSTEM_OBJECT_ID)
    )
    secret = _make_service_account(app, account_id="sa_new", name="ci-bot", scopes=[])

    resp = client.get("/system", headers=_bearer(secret))

    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_scopes_are_enforced_on_a_real_production_route(app, rbac_authz):
    """SEC3-1, the reproduced bypass, against an actual shipped route
    rather than a synthetic one: an SA holding the right RBAC role but
    not the route's scope must be refused; adding the scope admits it."""
    from py_authz.control_plane.routes import health as health_routes
    from py_authz.core.metrics import Metrics

    app.include_router(health_routes.router, prefix="/api/v1")
    app.state.metrics = Metrics()
    client = TestClient(app)

    no_scope = _make_service_account(app, account_id="sa_1", name="no-scope", scopes=[])
    scoped = _make_service_account(
        app, account_id="sa_2", name="scoped", scopes=[Scope.METRICS_READ.value]
    )
    for sa in ("sa_1", "sa_2"):
        await rbac_authz.grant(
            Identity(id=f"service_account:{sa}"), "owner", System(id=SYSTEM_OBJECT_ID)
        )

    assert client.get("/api/v1/metrics", headers=_bearer(no_scope)).status_code == 403
    assert client.get("/api/v1/metrics", headers=_bearer(scoped)).status_code == 200


def test_unknown_or_malformed_account_ids_are_not_tracked_by_the_rate_limiter(client, app):
    """SEC3-9: 20,000 unauthenticated requests with made-up ids used to
    leave 20,000 tracked keys behind."""
    limiter = app.state.service_account_rate_limiter

    for i in range(50):
        assert client.get("/system", headers=_bearer(f"pasa_sa_nope{i}.x")).status_code == 401
        assert client.get("/system", headers=_bearer(f"pasa_garbage{i}")).status_code == 401

    assert limiter._failure_times == {}


def test_in_memory_rate_limiter_sweeps_expired_keys(monkeypatch):
    import asyncio

    from py_authz.control_plane import rate_limit

    limiter = rate_limit.InMemoryRateLimiter(rate_limit.RateLimitPolicy(lockout_seconds=1))
    monkeypatch.setattr(rate_limit.InMemoryRateLimiter, "MAX_TRACKED_KEYS", 5)
    clock = [1000.0]
    monkeypatch.setattr(rate_limit.time, "monotonic", lambda: clock[0])

    async def run():
        for i in range(5):
            await limiter.record_failure(f"sa_{i}")
        clock[0] += 10  # every window has expired
        await limiter.record_failure("sa_new")

    asyncio.run(run())

    assert set(limiter._failure_times) == {"sa_new"}


@pytest.mark.asyncio
async def test_a_verified_secret_skips_argon2_until_the_hash_changes(client, app, monkeypatch):
    """REL3-13: argon2 used to run on the event loop on every request.
    Successful verifications are cached against the *stored hash*, so a
    rotate/revoke invalidates the cache immediately."""
    from py_authz.control_plane import auth as auth_module

    auth_module._VERIFIED.clear()
    calls = []
    real_verify = auth_module.verify_secret

    def counting_verify(token, secret_hash):
        calls.append(token)
        return real_verify(token, secret_hash)

    monkeypatch.setattr(auth_module, "verify_secret", counting_verify)
    secret = _make_service_account(app, account_id="sa_1", name="ci-bot", scopes=[])

    for _ in range(3):
        assert client.get("/me", headers=_bearer(secret)).status_code == 200
    assert len(calls) == 1

    # Rotation replaces the stored hash: the old secret is re-verified
    # (and now fails) instead of being served from the cache.
    from py_authz.control_plane.security import generate_secret, hash_secret

    app.state.service_account_store.accounts["sa_1"].secret_hash = hash_secret(
        generate_secret("sa_1")
    )
    assert client.get("/me", headers=_bearer(secret)).status_code == 401
    assert len(calls) == 2


@pytest.mark.asyncio
async def test_verified_secret_cache_is_a_bounded_lru(monkeypatch):
    """REL3-13: the cache of successful verifications evicts the least
    recently used entry once it's full, and a failed verify is never
    cached."""
    from py_authz.control_plane import auth as auth_module

    monkeypatch.setattr(auth_module, "_VERIFIED", auth_module.OrderedDict())
    monkeypatch.setattr(auth_module, "_VERIFIED_MAX", 2)
    calls = []

    def fake_verify(token, secret_hash):
        calls.append(token)
        return token != "bad"  # noqa: S105 — test token, not a secret

    monkeypatch.setattr(auth_module, "verify_secret", fake_verify)

    assert await auth_module._verify_cached("bad", "h") is False
    assert await auth_module._verify_cached("bad", "h") is False
    assert calls == ["bad", "bad"]  # failures are re-verified every time

    for token in ("a", "b"):
        assert await auth_module._verify_cached(token, "h") is True
    assert await auth_module._verify_cached("a", "h") is True  # hit: "a" is now most recent
    assert await auth_module._verify_cached("c", "h") is True  # evicts "b", the LRU entry
    assert len(auth_module._VERIFIED) == 2

    calls.clear()
    assert await auth_module._verify_cached("a", "h") is True
    assert calls == []  # still cached
    assert await auth_module._verify_cached("b", "h") is True
    assert calls == ["b"]  # was evicted, so verified again


class _TouchRecorder:
    def __init__(self):
        self.touched: list[str] = []

    async def touch_last_used(self, account_id):
        self.touched.append(account_id)


class _Record:
    def __init__(self, last_used_at):
        self.id = "sa_1"
        self.last_used_at = last_used_at


@pytest.mark.asyncio
@pytest.mark.parametrize("aware", [True, False], ids=["tz-aware", "naive"])
@pytest.mark.parametrize(
    ("age", "expect_touch"),
    [(timedelta(seconds=5), False), (timedelta(minutes=5), True)],
    ids=["recent", "stale"],
)
async def test_last_used_is_only_written_once_per_interval(aware, age, expect_touch):
    """REL3-13: `last_used_at` is written at most once a minute, whether
    the store hands back a tz-aware or a naive timestamp."""
    from py_authz.control_plane.auth import _touch_last_used_throttled

    now = datetime.now(UTC)
    last_used = now - age
    if not aware:
        last_used = last_used.replace(tzinfo=None)
    store = _TouchRecorder()

    await _touch_last_used_throttled(store, _Record(last_used))

    assert store.touched == (["sa_1"] if expect_touch else [])

"""
Live test for `py_authz.control_plane.app` — `create_app()`'s lifespan
(`_wire`/`_teardown`) constructs every store/client directly from
`ControlPlaneSettings` (real Postgres pools, a real `RedisRateLimiter`,
a real `OpenFGAClient.for_tenant` for the dogfooded RBAC store, a real
`OIDCJWTValidator`) with no injection seam for a mock — unlike every
route module, which takes its dependencies through `app.state`/`Depends`
and so is fully covered by `tests/control_plane/`'s mocked route tests.
This is the one place in the control-plane package that needs the real
four-service stack, same reasoning as this whole directory (see
`conftest.py`'s module docstring).

Requires OpenFGA + Postgres + Redis + Keycloak all reachable — run via
`make test-integration`.
"""

import pytest
from starlette.testclient import TestClient

from py_authz.clients.openfga import OpenFGAClient
from py_authz.control_plane.app import create_app
from py_authz.control_plane.settings import ControlPlaneSettings

from .conftest import (
    FGA_API_URL,
    KEYCLOAK_AUDIENCE,
    KEYCLOAK_ISSUER,
    REDIS_URL,
    requires_keycloak,
    requires_openfga,
    requires_postgres,
    requires_redis,
)


@pytest.fixture
async def rbac_store_id(fga_api_url):
    """A fresh, empty OpenFGA store for `_wire()`'s RBAC model sync to
    run against — separate from any tenant's store, matching
    `docs/control_plane.md` §3's own setup step."""
    client = OpenFGAClient(api_url=fga_api_url, store_id=None, model_id=None)
    try:
        store_id = await client.create_store(name="py-authz-control-plane-live-test")
        yield store_id
    finally:
        await client.aclose()


@pytest.fixture
def settings(postgres_schema, postgres_dsn, rbac_store_id):
    return ControlPlaneSettings(
        fga_api_url=FGA_API_URL,
        rbac_fga_api_url=FGA_API_URL,
        rbac_fga_store_id=rbac_store_id,
        postgres_dsn=postgres_dsn,
        redis_url=REDIS_URL,
        oidc_issuer=KEYCLOAK_ISSUER,
        oidc_audience=KEYCLOAK_AUDIENCE,
    )


@requires_openfga
@requires_postgres
@requires_redis
@requires_keycloak
def test_lifespan_wires_and_tears_down_every_dependency(settings):
    """`TestClient` used as a context manager drives Starlette's
    lifespan protocol — entering it runs `_wire()`, exiting runs
    `_teardown()`. Getting through both without raising, and having
    `/health` respond in between, is exactly what a real deployment's
    startup/shutdown does."""
    app = create_app(settings)

    with TestClient(app) as client:
        assert app.state.rbac_authz is not None
        assert app.state.multi_tenant_authz is not None
        assert app.state.redis_cache is not None
        assert app.state.oidc_validator is not None

        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["checks"]["openfga"] == "ok"

    # _teardown() ran on exit — a second close would raise if anything
    # here weren't already idempotent/tolerant of it, so the context
    # manager exiting cleanly (no exception propagated by pytest) is
    # the assertion.


@requires_openfga
@requires_postgres
@requires_keycloak
def test_lifespan_without_redis_configured_leaves_cache_routes_disabled(
    postgres_schema, postgres_dsn, rbac_store_id
):
    """`redis_url=None` is a supported deployment shape (see
    `deps.get_redis_cache`'s docstring) — `_wire()` must still complete,
    just with `redis_cache`/the rate limiter falling back to their
    in-process forms instead of failing to start."""
    settings = ControlPlaneSettings(
        fga_api_url=FGA_API_URL,
        rbac_fga_api_url=FGA_API_URL,
        rbac_fga_store_id=rbac_store_id,
        postgres_dsn=postgres_dsn,
        redis_url=None,
        oidc_issuer=KEYCLOAK_ISSUER,
        oidc_audience=KEYCLOAK_AUDIENCE,
    )
    app = create_app(settings)

    with TestClient(app) as client:
        assert app.state.redis_cache is None

        resp = client.get("/health")
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# DX3-1: an authenticated, end-to-end pass through the real stack.
#
# The two tests above only prove the lifespan wires up. Nothing exercised
# a real Keycloak token -> OIDCJWTValidator -> break-glass bootstrap -> a
# real OpenFGA RBAC check -> a route, which is how SEC3-3 (service-account
# principals using a subject type the RBAC model never declared) shipped:
# the unit tests' type-permissive in-memory fake accepted it, and the
# manual live pass `09` describes never created a service account.
# ---------------------------------------------------------------------------


def _alice_token_and_sub() -> tuple[str, str]:
    import anyio
    import jwt

    from .test_keycloak_live import _fetch_token

    token = anyio.run(_fetch_token)
    sub = jwt.decode(token, options={"verify_signature": False})["sub"]
    return token, sub


@requires_openfga
@requires_postgres
@requires_redis
@requires_keycloak
def test_operator_and_service_account_flows_end_to_end(settings):
    token, sub = _alice_token_and_sub()
    settings.break_glass_subject = sub
    settings.model_module = "examples.models"
    operator = {"Authorization": f"Bearer {token}"}

    app = create_app(settings)
    with TestClient(app) as client:
        # Break-glass bootstrap makes the first matching operator owner.
        me = client.get("/api/v1/auth/me", headers=operator)
        assert me.status_code == 200, me.text
        assert me.json()["system_role"] == "owner"

        # Provision a tenant (real OpenFGA store + model sync).
        resp = client.post("/api/v1/tenants", headers=operator, json={"tenant_id": "acme-live"})
        assert resp.status_code == 200, resp.text

        # Tenant routes need an explicit tenant grant (scopes don't imply).
        resp = client.post(
            "/api/v1/operators/roles",
            headers=operator,
            json={"subject": sub, "scope": "tenant", "tenant_id": "acme-live", "role": "owner"},
        )
        assert resp.status_code == 200, resp.text

        # Manual grant with a mandatory reason, then find it in the audit
        # log by *tenant id* (regression for 09's tenant-vs-store filter bug).
        resp = client.post(
            "/api/v1/tenants/acme-live/grants",
            headers=operator,
            json={
                "user": "user:bob",
                "relation": "viewer",
                "object": {"type": "document", "id": "roadmap"},
                "reason": "live e2e",
            },
        )
        assert resp.status_code == 200, resp.text

        # Audit writes are background tasks — poll briefly for the row.
        import time

        rows: list = []
        for _ in range(30):
            audit = client.get(
                "/api/v1/audit-logs", headers=operator, params={"tenant_id": "acme-live"}
            )
            assert audit.status_code == 200, audit.text
            rows = [r for r in audit.json()["items"] if r.get("resource") == "document:roadmap"]
            if rows:
                break
            time.sleep(0.1)
        assert rows, "grant never appeared in the tenant's audit log"

        # ---- Service account: scope + role, against the REAL RBAC store ----
        resp = client.post(
            "/api/v1/service-accounts",
            headers=operator,
            json={"name": "ci-bot", "scopes": ["tenants:read"]},
        )
        assert resp.status_code == 200, resp.text
        sa_id, sa_secret = resp.json()["id"], resp.json()["secret"]
        sa = {"Authorization": f"Bearer {sa_secret}"}

        # No role yet -> denied by RBAC (not a 5xx from OpenFGA rejecting
        # an unknown subject type, which is what SEC3-3 produced).
        resp = client.get("/api/v1/tenants/acme-live", headers=sa)
        assert resp.status_code == 403, resp.text

        resp = client.post(
            "/api/v1/operators/roles",
            headers=operator,
            json={
                "subject": sa_id,
                "subject_kind": "service_account",
                "scope": "tenant",
                "tenant_id": "acme-live",
                "role": "auditor",
            },
        )
        assert resp.status_code == 200, resp.text

        me = client.get("/api/v1/auth/me", headers=sa)
        assert me.json()["id"] == f"service_account:{sa_id}"

        # Role + scope -> allowed.
        resp = client.get("/api/v1/tenants/acme-live", headers=sa)
        assert resp.status_code == 200, resp.text

        # Role but no scope for this route (tuples:read) -> denied (SEC3-1).
        resp = client.get("/api/v1/tenants/acme-live/tuples", headers=sa)
        assert resp.status_code == 403, resp.text

        # Revoke removes its role grants in the real store too.
        resp = client.delete(f"/api/v1/service-accounts/{sa_id}", headers=operator)
        assert resp.status_code == 200, resp.text
        assert resp.json()["roles_removed"] == 1
        roles = client.get(
            "/api/v1/operators/roles",
            headers=operator,
            params={"scope": "tenant", "tenant_id": "acme-live"},
        ).json()["items"]
        assert all(r["subject"] != f"service_account:{sa_id}" for r in roles)

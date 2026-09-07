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

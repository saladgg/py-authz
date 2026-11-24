"""
Smoke tests for py_authz.control_plane.app.create_app (CP-1).

Only exercises route wiring/declaration — `_wire()`'s lifespan (real
Postgres/OpenFGA/Redis connections) is intentionally not triggered here;
that's exactly what a `docker compose`-backed integration test would
cover, not a unit test.
"""

from py_authz.control_plane.app import create_app
from py_authz.control_plane.settings import ControlPlaneSettings


def _settings(**overrides) -> ControlPlaneSettings:
    defaults = {
        "fga_api_url": "http://fga.local",
        "rbac_fga_api_url": "http://fga.local",
        "rbac_fga_store_id": "store1",
        "postgres_dsn": "postgres://fake",
        "oidc_issuer": "https://issuer.local",
        "oidc_audience": "aud",
    }
    defaults.update(overrides)
    return ControlPlaneSettings(**defaults)


def test_create_app_builds_without_error():
    app = create_app(_settings())
    assert app.title == "py-authz control-plane API"


def test_health_route_is_unversioned_and_unauthenticated():
    app = create_app(_settings())
    schema = app.openapi()

    assert "/health" in schema["paths"]
    assert schema["paths"]["/health"]["get"].get("security") in (None, [])


def test_every_other_route_is_versioned_under_api_v1():
    app = create_app(_settings())
    schema = app.openapi()

    other_paths = [p for p in schema["paths"] if p != "/health"]
    assert other_paths, "expected at least one non-health route"
    assert all(p.startswith("/api/v1") for p in other_paths)


def test_expected_route_surface_matches_the_architecture_doc():
    app = create_app(_settings())
    schema = app.openapi()

    expected = {
        "/health",
        "/api/v1/metrics",
        "/api/v1/auth/me",
        "/api/v1/service-accounts",
        "/api/v1/service-accounts/{account_id}",
        "/api/v1/service-accounts/{account_id}/rotate",
        "/api/v1/operators",
        "/api/v1/operators/roles",
        "/api/v1/tenants",
        "/api/v1/tenants/{tenant_id}",
        "/api/v1/tenants/{tenant_id}/provision",
        "/api/v1/tenants/{tenant_id}/tuples",
        "/api/v1/tenants/{tenant_id}/grants",
        "/api/v1/tenants/{tenant_id}/revokes",
        "/api/v1/tenants/{tenant_id}/models/history",
        "/api/v1/tenants/{tenant_id}/models/rollback",
        "/api/v1/models",
        "/api/v1/models/sync",
        "/api/v1/migrations",
        "/api/v1/migrations/{job_id}",
        "/api/v1/audit-logs",
        "/api/v1/cache/stats",
        "/api/v1/cache/invalidate",
    }
    assert set(schema["paths"]) == expected


def test_tenant_manager_is_always_wired_with_a_provisioning_lock():
    """REL3-2: `_wire()` used to build `TenantManager` without a lock
    manager, so concurrent creates orphaned OpenFGA stores. Checks the
    wiring source, since `_wire()` itself needs live services (it's
    exercised end-to-end by tests/live/test_control_plane_live.py)."""
    import inspect

    from py_authz.control_plane import app as app_module

    source = inspect.getsource(app_module._wire)
    assert "lock_manager=lock_manager" in source
    assert "InProcessLockManager()" in source

"""
Thin `Request -> app.state.<thing>` accessors, used as FastAPI `Depends(...)`
throughout `routes/`. Everything they return is built once, in `app.py`'s
lifespan, and shared across requests — these exist so route handlers
depend on a named, overridable (via `app.dependency_overrides`, e.g. in
tests) accessor instead of reaching into `request.app.state` directly
everywhere.
"""

from fastapi import Request

from py_authz.control_plane.settings import ControlPlaneSettings


def get_settings(request: Request) -> ControlPlaneSettings:
    return request.app.state.settings


def get_migration_concurrency(request: Request) -> int:
    """`CONTROL_PLANE_MIGRATION_CONCURRENCY` (REL3-11 — previously parsed
    into settings but never passed to `MigrationManager`). Falls back to
    `MigrationManager`'s own default when the app was built without
    settings (route-level unit tests)."""
    settings = getattr(request.app.state, "settings", None)
    return settings.migration_concurrency if settings is not None else 10


def get_rbac_authz(request: Request):
    return request.app.state.rbac_authz


def get_multi_tenant_authz(request: Request):
    return request.app.state.multi_tenant_authz


def get_tenant_store(request: Request):
    return request.app.state.tenant_store


def get_model_registry(request: Request):
    return request.app.state.model_registry


def get_tenant_manager(request: Request):
    return request.app.state.tenant_manager


def get_migration_manager(request: Request):
    return request.app.state.migration_manager


def get_service_account_store(request: Request):
    return request.app.state.service_account_store


def get_operator_store(request: Request):
    return request.app.state.operator_store


def get_model_version_store(request: Request):
    return request.app.state.model_version_store


def get_job_store(request: Request):
    return request.app.state.job_store


def get_job_runner(request: Request):
    return request.app.state.job_runner


def get_audit_query(request: Request):
    return request.app.state.audit_query


def get_redis_cache(request: Request):
    """`None` if this deployment has no Redis configured — routes using
    this (CP-9) must handle that (503, not a crash)."""
    return getattr(request.app.state, "redis_cache", None)


def get_metrics(request: Request):
    return request.app.state.metrics


def get_readiness_checks(request: Request) -> dict:
    """Name -> zero-argument async callable, built by `_wire()` (REL3-7)."""
    return request.app.state.readiness_checks

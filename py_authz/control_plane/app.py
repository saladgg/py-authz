"""
Control-plane API app factory (CP-1).

`create_app()` builds the FastAPI app and wires every dependency the
routes need (Postgres pools, the dedicated RBAC OpenFGA store/model, the
product `MultiTenantAuthz`, service accounts, jobs, ...) in its lifespan
— see `deps.py` for how routes reach what's built here. Nothing below
reimplements engine logic: every piece is a `py_authz` class already used
by the CLI/adapters, just constructed from `ControlPlaneSettings` instead
of CLI flags.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI

from py_authz.adapters.oidc import OIDCJWTValidator
from py_authz.api import Authz, MultiTenantAuthz
from py_authz.audit.postgres import PostgresAuditLogger, PostgresAuditQuery
from py_authz.cache.redis import RedisCache
from py_authz.cli.utils import load_module
from py_authz.clients.openfga import OpenFGAClient
from py_authz.control_plane import rbac_model
from py_authz.control_plane.bootstrap import BreakGlassBootstrapper
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.jobs import JobRunner, JobStore
from py_authz.control_plane.logging_middleware import install_request_logging
from py_authz.control_plane.model_versions import ModelVersionStore
from py_authz.control_plane.operators import OperatorStore
from py_authz.control_plane.rate_limit import InMemoryRateLimiter, RateLimitPolicy, RedisRateLimiter
from py_authz.control_plane.routes import audit as audit_routes
from py_authz.control_plane.routes import auth_routes
from py_authz.control_plane.routes import cache as cache_routes
from py_authz.control_plane.routes import health as health_routes
from py_authz.control_plane.routes import migrations as migrations_routes
from py_authz.control_plane.routes import models as models_routes
from py_authz.control_plane.routes import operators as operators_routes
from py_authz.control_plane.routes import service_accounts as service_accounts_routes
from py_authz.control_plane.routes import tenants as tenants_routes
from py_authz.control_plane.routes import tuples as tuples_routes
from py_authz.control_plane.service_accounts import ServiceAccountStore
from py_authz.control_plane.settings import ControlPlaneSettings
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthzError
from py_authz.core.logging import setup_logging
from py_authz.core.metrics import Metrics
from py_authz.core.migrations_manager import MigrationManager
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_resolver import StoreBackedResolver
from py_authz.storage.postgres import PostgresModelRegistry, PostgresTenantStore
from py_authz.storage.schema import apply_schema
from py_authz.utils.deps import require_redis

#: Every connect()-lifecycle store built in `_wire(...)`, keyed by the
#: `app.state` attribute name — used by both `_wire`/`_teardown` so the
#: two can't drift out of sync on which stores actually need closing.
_STORE_STATE_NAMES = (
    "tenant_store",
    "model_registry",
    "audit_query",
    "service_account_store",
    "operator_store",
    "model_version_store",
    "job_store",
)


async def _wire(app: FastAPI, settings: ControlPlaneSettings) -> None:
    setup_logging()

    # Import the adopter's own `@ResourceModel` classes, if configured —
    # otherwise `GET /models`/`POST /models/sync` (CP-6) only ever see
    # the bare `user` type, since nothing else would have registered
    # into `py_authz.modeling.registry.registry` (see `settings.
    # model_module`'s docstring, and the CLI's own `--module` flag for
    # the equivalent one-shot-command version of this).
    if settings.model_module:
        load_module(settings.model_module)

    app.state.metrics = Metrics()

    # One Postgres DSN for everything (existing tenants/tenant_models/
    # audit_logs tables plus the new control-plane ones) — `apply_schema()`
    # covers both (see storage/schema.py's SCHEMA_FILES).
    await apply_schema(settings.postgres_dsn)

    app.state.tenant_store = PostgresTenantStore(settings.postgres_dsn)
    app.state.model_registry = PostgresModelRegistry(settings.postgres_dsn)
    app.state.audit_query = PostgresAuditQuery(settings.postgres_dsn)
    app.state.service_account_store = ServiceAccountStore(settings.postgres_dsn)
    app.state.operator_store = OperatorStore(settings.postgres_dsn)
    app.state.model_version_store = ModelVersionStore(settings.postgres_dsn)
    app.state.job_store = JobStore(settings.postgres_dsn)
    for name in _STORE_STATE_NAMES:
        await getattr(app.state, name).connect()

    audit_logger = PostgresAuditLogger(settings.postgres_dsn)
    await audit_logger.connect()
    app.state._audit_logger = audit_logger  # closed alongside the stores above

    app.state.job_runner = JobRunner(app.state.job_store)

    app.state.tenant_manager = TenantManager(
        api_url=settings.fga_api_url, tenant_store=app.state.tenant_store
    )
    app.state.migration_manager = MigrationManager(
        api_url=settings.fga_api_url,
        tenant_store=app.state.tenant_store,
        model_registry=app.state.model_registry,
    )

    app.state.redis_cache = RedisCache(settings.redis_url) if settings.redis_url else None

    # CP-16: service-account auth lockout. Redis-backed (shared across
    # instances) when Redis is configured, otherwise an in-process
    # fallback — matches `JobRunner`'s own single-process-for-v1 stance
    # (see rate_limit.py's module docstring) rather than making Redis a
    # hard requirement just for this.
    rate_limit_policy = RateLimitPolicy(
        max_failed_attempts=settings.service_account_rate_limit_max_attempts,
        lockout_seconds=settings.service_account_rate_limit_lockout_seconds,
    )
    if settings.redis_url:
        redis_module = require_redis()
        app.state._rate_limit_redis_client = redis_module.from_url(settings.redis_url)
        app.state.service_account_rate_limiter = RedisRateLimiter(
            app.state._rate_limit_redis_client, rate_limit_policy
        )
    else:
        app.state._rate_limit_redis_client = None
        app.state.service_account_rate_limiter = InMemoryRateLimiter(rate_limit_policy)

    app.state.multi_tenant_authz = MultiTenantAuthz(
        api_url=settings.fga_api_url,
        model_id=None,
        tenant_resolver=StoreBackedResolver(app.state.tenant_store),
        # Explicit provisioning only (`POST /tenants`/`.../provision`,
        # CP-4) — a management API must never silently create a tenant's
        # store just because someone resolved it, unlike an end-user-
        # facing app where auto-provisioning-on-first-use is convenient.
        tenant_manager=None,
        cache=app.state.redis_cache,
        audit_logger=audit_logger,
        metrics=app.state.metrics,
        max_cached_tenants=settings.max_cached_tenants,
    )

    # The dogfooded RBAC store — its own dedicated OpenFGA store, never
    # mixed with any tenant's (see rbac_model.py's module docstring).
    rbac_fga_client = OpenFGAClient.for_tenant(
        api_url=settings.rbac_fga_api_url,
        store_id=settings.rbac_fga_store_id,
        model_id=settings.rbac_fga_model_id,
    )
    rbac_syncer = ModelSync(rbac_fga_client, model_factory=rbac_model.generate_rbac_model)
    rbac_fga_client.model_id = await rbac_syncer.sync()

    rbac_authz = Authz(
        AuthzEngine(
            fga_client=rbac_fga_client, audit_logger=audit_logger, metrics=app.state.metrics
        )
    )
    app.state.rbac_authz = rbac_authz
    app.state.rbac_fga_client = rbac_fga_client
    # Health probe target (see routes/health.py) — the RBAC store is
    # always guaranteed to exist once this function returns, unlike any
    # one particular tenant's.
    app.state.product_fga_client = rbac_fga_client

    app.state.bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz,
        rbac_fga_client=rbac_fga_client,
        break_glass_subject=settings.break_glass_subject,
    )

    app.state.oidc_validator = OIDCJWTValidator(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
    )


async def _teardown(app: FastAPI) -> None:
    await app.state.multi_tenant_authz.aclose()
    await app.state.rbac_fga_client.aclose()
    await app.state.job_runner.aclose()
    await app.state._audit_logger.close()
    for name in _STORE_STATE_NAMES:
        await getattr(app.state, name).close()
    if app.state.redis_cache is not None:
        await app.state.redis_cache.close()
    if app.state._rate_limit_redis_client is not None:
        await app.state._rate_limit_redis_client.aclose()


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    await _wire(app, app.state.settings)
    try:
        yield
    finally:
        await _teardown(app)


API_PREFIX = "/api/v1"

#: Every authenticated, versioned router — mounted under `API_PREFIX`.
#: Module-level (rather than inline in `create_app`) so
#: `tests/control_plane/test_route_scopes.py` can walk exactly the routes
#: the app serves and assert each one declares a service-account scope
#: (SEC3-1).
API_ROUTERS = (
    health_routes.router,  # /metrics — authenticated, versioned
    auth_routes.router,
    service_accounts_routes.router,
    operators_routes.router,
    tenants_routes.router,
    models_routes.router,
    migrations_routes.router,
    audit_routes.router,
    tuples_routes.router,
    cache_routes.router,
)


def create_app(settings: ControlPlaneSettings | None = None) -> FastAPI:
    """
    Build the control-plane API app. `settings` defaults to
    `ControlPlaneSettings.from_env()` — pass one explicitly in tests, or
    for a deployment that reads its configuration some other way.
    """
    app = FastAPI(title="py-authz control-plane API", lifespan=_lifespan)
    app.state.settings = settings or ControlPlaneSettings.from_env()

    app.add_exception_handler(AuthzError, authz_error_handler)
    install_request_logging(app)  # CP-18

    # `/health` is deliberately unauthenticated and unversioned — a load
    # balancer/orchestrator probe has no operator session or
    # service-account credential to present.
    app.include_router(health_routes.health_router)

    for router in API_ROUTERS:
        app.include_router(router, prefix=API_PREFIX)

    return app

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

import logging
from collections.abc import AsyncIterator
from contextlib import AsyncExitStack, asynccontextmanager

from fastapi import FastAPI

from py_authz.adapters.oidc import OIDCJWTValidator
from py_authz.api import Authz, MultiTenantAuthz
from py_authz.audit.postgres import PostgresAuditLogger, PostgresAuditQuery
from py_authz.cache.redis import RedisCache
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
from py_authz.core.locks import InProcessLockManager, RedisLockManager
from py_authz.core.logging import setup_logging
from py_authz.core.metrics import Metrics
from py_authz.core.migrations_manager import MigrationManager
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_resolver import StoreBackedResolver
from py_authz.storage.postgres import PostgresModelRegistry, PostgresTenantStore
from py_authz.storage.schema import apply_schema
from py_authz.utils.deps import redis_from_url
from py_authz.utils.modules import load_module

#: Every connect()-lifecycle store built in `_wire(...)`, keyed by the
#: `app.state` attribute name — used by both `_wire`/`_teardown` so the
#: two can't drift out of sync on which stores actually need closing.
logger = logging.getLogger("py_authz.control_plane")

_STORE_STATE_NAMES = (
    "tenant_store",
    "model_registry",
    "audit_query",
    "service_account_store",
    "operator_store",
    "model_version_store",
    "job_store",
)


async def _wire(app: FastAPI, settings: ControlPlaneSettings, stack: AsyncExitStack) -> None:
    """
    Build every store/client the routes use. Each resource registers its
    own cleanup on `stack` the moment it's opened (REL3-12), so:

    - a failure partway through startup (e.g. the RBAC model sync) still
      closes everything opened before it — previously `_wire()` ran
      outside the lifespan's `try`, leaking every pool already open;
    - teardown runs in reverse order of construction, and one failing
      close no longer skips all the others (`AsyncExitStack` keeps
      unwinding and re-raises at the end).
    """
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
    if settings.apply_schema_on_startup:
        await apply_schema(settings.postgres_dsn)

    pool = {
        "pool_min_size": settings.postgres_pool_min_size,
        "pool_max_size": settings.postgres_pool_max_size,
    }
    app.state.tenant_store = PostgresTenantStore(settings.postgres_dsn, **pool)
    app.state.model_registry = PostgresModelRegistry(settings.postgres_dsn, **pool)
    app.state.audit_query = PostgresAuditQuery(settings.postgres_dsn, **pool)
    app.state.service_account_store = ServiceAccountStore(settings.postgres_dsn, **pool)
    app.state.operator_store = OperatorStore(settings.postgres_dsn, **pool)
    app.state.model_version_store = ModelVersionStore(settings.postgres_dsn, **pool)
    app.state.job_store = JobStore(settings.postgres_dsn, **pool)
    for name in _STORE_STATE_NAMES:
        store = getattr(app.state, name)
        await store.connect()
        stack.push_async_callback(store.close)

    audit_logger = PostgresAuditLogger(settings.postgres_dsn, **pool)
    await audit_logger.connect()
    # Registered before every audit-producing engine below, so it closes
    # only after they've flushed (REL3-8).
    stack.push_async_callback(audit_logger.close)
    app.state._audit_logger = audit_logger

    # REL3-3: settle jobs orphaned by a previous process (single-process
    # deployment assumed — see `JobStore.fail_interrupted`).
    interrupted = await app.state.job_store.fail_interrupted()
    if interrupted:
        logger.warning("marked %d interrupted control-plane job(s) as failed", interrupted)
    app.state.job_runner = JobRunner(app.state.job_store)
    # Unwound before the stores/audit logger registered above it, so
    # in-flight jobs finish (or are cancelled and recorded) while their
    # stores are still open.
    stack.push_async_callback(app.state.job_runner.aclose)

    # One Redis client shared by the provisioning lock and the
    # service-account rate limiter (below), with bounded socket timeouts
    # (REL3-5).
    app.state._redis_client = redis_from_url(settings.redis_url) if settings.redis_url else None
    if app.state._redis_client is not None:
        stack.push_async_callback(app.state._redis_client.aclose)

    # REL3-2: provisioning was unlocked here, so a double-clicked "Create
    # tenant" (or two replicas) created two OpenFGA stores and orphaned
    # one. Redis-backed when configured (coordinates across replicas),
    # otherwise in-process.
    lock_manager = (
        RedisLockManager(app.state._redis_client)
        if app.state._redis_client is not None
        else InProcessLockManager()
    )
    app.state.tenant_manager = TenantManager(
        api_url=settings.fga_api_url,
        tenant_store=app.state.tenant_store,
        lock_manager=lock_manager,
    )
    app.state.migration_manager = MigrationManager(
        api_url=settings.fga_api_url,
        tenant_store=app.state.tenant_store,
        model_registry=app.state.model_registry,
    )

    app.state.redis_cache = (
        RedisCache(client=app.state._redis_client) if app.state._redis_client is not None else None
    )

    # CP-16: service-account auth lockout. Redis-backed (shared across
    # instances) when Redis is configured, otherwise an in-process
    # fallback — matches `JobRunner`'s own single-process-for-v1 stance
    # (see rate_limit.py's module docstring) rather than making Redis a
    # hard requirement just for this.
    rate_limit_policy = RateLimitPolicy(
        max_failed_attempts=settings.service_account_rate_limit_max_attempts,
        lockout_seconds=settings.service_account_rate_limit_lockout_seconds,
    )
    if app.state._redis_client is not None:
        app.state.service_account_rate_limiter = RedisRateLimiter(
            app.state._redis_client, rate_limit_policy
        )
    else:
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
    # `Authz.aclose()` flushes each tenant engine's audit writes first.
    stack.push_async_callback(app.state.multi_tenant_authz.aclose)

    # The dogfooded RBAC store — its own dedicated OpenFGA store, never
    # mixed with any tenant's (see rbac_model.py's module docstring).
    rbac_fga_client = OpenFGAClient.for_tenant(
        api_url=settings.rbac_fga_api_url,
        store_id=settings.rbac_fga_store_id,
        model_id=settings.rbac_fga_model_id,
    )
    stack.push_async_callback(rbac_fga_client.aclose)
    rbac_syncer = ModelSync(rbac_fga_client, model_factory=rbac_model.generate_rbac_model)
    rbac_fga_client.model_id = await rbac_syncer.sync()

    rbac_authz = Authz(
        AuthzEngine(
            fga_client=rbac_fga_client, audit_logger=audit_logger, metrics=app.state.metrics
        )
    )
    app.state.rbac_authz = rbac_authz
    app.state.rbac_fga_client = rbac_fga_client
    # Flush the RBAC engine's audit writes (role grants carry reason/actor).
    stack.push_async_callback(rbac_authz._engine.flush_audit_logs)

    _wire_readiness_checks(app, settings, stack)

    app.state.bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz,
        rbac_fga_client=rbac_fga_client,
        break_glass_subject=settings.break_glass_subject,
    )

    app.state.oidc_validator = OIDCJWTValidator(
        issuer=settings.oidc_issuer,
        audience=settings.oidc_audience,
        jwks_url=settings.oidc_jwks_url,
        expected_typ=settings.oidc_expected_typ,
        allowed_azp=settings.oidc_allowed_azp,
    )


def _wire_readiness_checks(
    app: FastAPI, settings: ControlPlaneSettings, stack: AsyncExitStack
) -> None:
    """Dependencies `/readyz` checks (REL3-7). OpenFGA probe clients are
    separate from the serving ones: no retries and a short timeout, so a
    probe answers within the orchestrator's own deadline."""

    def _probe_client(api_url: str) -> OpenFGAClient:
        return OpenFGAClient(
            api_url=api_url, store_id=None, model_id=None, timeout=1.0, max_retries=0
        )

    probe_clients = {"openfga": _probe_client(settings.fga_api_url)}
    if settings.rbac_fga_api_url.rstrip("/") != settings.fga_api_url.rstrip("/"):
        probe_clients["openfga_rbac"] = _probe_client(settings.rbac_fga_api_url)
    for client in probe_clients.values():
        stack.push_async_callback(client.aclose)

    checks = {"postgres": app.state.tenant_store.ping}
    checks.update({name: client.ping for name, client in probe_clients.items()})
    if app.state._redis_client is not None:
        checks["redis"] = app.state._redis_client.ping
    app.state.readiness_checks = checks


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    async with AsyncExitStack() as stack:
        await _wire(app, app.state.settings, stack)
        yield


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
    settings = settings or ControlPlaneSettings.from_env()
    # SEC3-11: the interactive docs and OpenAPI schema publish the whole
    # admin API surface unauthenticated — off unless explicitly enabled.
    app = FastAPI(
        title="py-authz control-plane API",
        lifespan=_lifespan,
        docs_url="/docs" if settings.expose_docs else None,
        redoc_url="/redoc" if settings.expose_docs else None,
        openapi_url="/openapi.json" if settings.expose_docs else None,
    )
    app.state.settings = settings

    app.add_exception_handler(AuthzError, authz_error_handler)
    install_request_logging(app)  # CP-18

    # `/health` is deliberately unauthenticated and unversioned — a load
    # balancer/orchestrator probe has no operator session or
    # service-account credential to present.
    app.include_router(health_routes.health_router)

    for router in API_ROUTERS:
        app.include_router(router, prefix=API_PREFIX)

    return app

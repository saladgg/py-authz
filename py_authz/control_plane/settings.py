"""
Environment-driven configuration for the control-plane API.

Mirrors the CLI's own "env var fallback, explicit override wins"
philosophy (`cli/main.py`'s `_ENV_VARS`), but there's no CLI flag layer
here — a long-running service reads its configuration once, at process
startup, from the environment. Every field has a doc comment on the env
var it comes from so `docs/`/`.env.example` (CP-19, out of this pass's
scope) has one place to stay in sync with.
"""

import os
from dataclasses import dataclass, field

from py_authz.core.exceptions import ConfigurationError


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigurationError(f"{name} is required to start the control-plane API")
    return value


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "on")


@dataclass
class ControlPlaneSettings:
    """
    Args mirror the environment variables `from_env()` reads them from —
    construct directly (bypassing the environment) in tests.
    """

    # -- Product OpenFGA (the tenants MultiTenantAuthz/TenantManager/
    #    MigrationManager manage) --
    fga_api_url: str

    # -- Control-plane's own dedicated RBAC OpenFGA store (see
    #    rbac_model.py) — defaults to the same server as the product
    #    OpenFGA instance, since "no new infrastructure surface" is this
    #    backlog's own stated preference (see the architecture doc's open
    #    questions), but a distinct store on it. --
    rbac_fga_api_url: str
    rbac_fga_store_id: str
    rbac_fga_model_id: str | None = None

    # -- The adopter's own `@ResourceModel` classes must be imported into
    #    this process for `generate_model()`/`ModelSync` (GET /models,
    #    POST /models/sync — CP-6) to see anything beyond the bare `user`
    #    type — same idea as the CLI's `--module` flag
    #    (`cli/main.py`/`cli/utils.py:load_module`), just read from the
    #    environment instead of a flag since this is a long-running
    #    service, not a one-shot command. `None` (the default) means the
    #    control-plane API's own process is expected to already import
    #    the adopter's model module some other way (e.g. a shared
    #    entrypoint) before `create_app()` runs. --
    model_module: str | None = None

    # -- Postgres: tenants/tenant_models/audit_logs (existing tables) plus
    #    operators/service_accounts/model_versions/control_plane_jobs
    #    (new — see storage/schema.py's SCHEMA_FILES). One DSN, same
    #    database, per the architecture doc §2.2/§3. --
    postgres_dsn: str = ""

    # -- Redis: cache stats/invalidation (CP-9). Optional — a deployment
    #    with no Redis simply can't serve the cache screen's routes. --
    redis_url: str | None = None

    # -- Operator authentication (CP-2): any standards-compliant OIDC
    #    provider, via OIDCJWTValidator. --
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str | None = None

    # -- Break-glass bootstrap (CP-2): the *only* way the very first
    #    operator gets `system#owner` — an operator who doesn't exist yet
    #    can't be granted a role by one who does. Consumed once, only
    #    when the RBAC store has zero grants on the `system` object; see
    #    `bootstrap.py`. Empty/unset means "no break-glass" — a fresh
    #    deployment with this unset can never bootstrap its first owner
    #    and must have one seeded some other way (e.g. writing the tuple
    #    directly via the OpenFGA API once, out of band).
    break_glass_subject: str | None = None

    #: Max cached tenants held by the control-plane's `MultiTenantAuthz`
    #: (see SEC2-3/ARCH2-9) — same bound, same default, as the library's
    #: own.
    max_cached_tenants: int | None = 1000

    #: Concurrency bound for `MigrationManager.migrate_all()` jobs (CP-7).
    migration_concurrency: int = 10

    # -- Rate limiting on the service-account secret-verification path
    #    (CP-16) — see `rate_limit.RateLimitPolicy`. --
    service_account_rate_limit_max_attempts: int = 5
    service_account_rate_limit_lockout_seconds: int = 300

    # -- Postgres pools (REL3-14). Every control-plane store opens its own
    #    pool; these used to be fixed at min == max (10/5 each), so one
    #    replica opened ~60 connections at boot with no way to tune it —
    #    two replicas or a rolling deploy exhausted Postgres's default
    #    `max_connections=100`. Now each starts with `min` and grows on
    #    demand up to `max`. --
    postgres_pool_min_size: int = 1
    postgres_pool_max_size: int = 5

    #: Run the bundled DDL (`apply_schema()`) at startup (REL3-10 part).
    #: Set false in production and apply schema out of band, so replicas
    #: don't race DDL on every boot.
    apply_schema_on_startup: bool = True

    #: Serve `/docs`, `/redoc` and `/openapi.json` (SEC3-11). Off by
    #: default: they publish the full admin API surface without
    #: authentication.
    expose_docs: bool = False

    extra: dict = field(default_factory=dict)

    @classmethod
    def from_env(cls) -> "ControlPlaneSettings":
        fga_api_url = _required("FGA_API_URL")
        return cls(
            fga_api_url=fga_api_url,
            rbac_fga_api_url=os.environ.get("CONTROL_PLANE_FGA_API_URL", fga_api_url),
            rbac_fga_store_id=_required("CONTROL_PLANE_FGA_STORE_ID"),
            rbac_fga_model_id=os.environ.get("CONTROL_PLANE_FGA_MODEL_ID"),
            model_module=os.environ.get("CONTROL_PLANE_MODEL_MODULE"),
            postgres_dsn=_required("CONTROL_PLANE_POSTGRES_DSN"),
            redis_url=os.environ.get("CONTROL_PLANE_REDIS_URL"),
            oidc_issuer=_required("CONTROL_PLANE_OIDC_ISSUER"),
            oidc_audience=_required("CONTROL_PLANE_OIDC_AUDIENCE"),
            oidc_jwks_url=os.environ.get("CONTROL_PLANE_OIDC_JWKS_URL"),
            break_glass_subject=os.environ.get("CONTROL_PLANE_BREAK_GLASS_SUBJECT"),
            max_cached_tenants=int(os.environ["CONTROL_PLANE_MAX_CACHED_TENANTS"])
            if os.environ.get("CONTROL_PLANE_MAX_CACHED_TENANTS")
            else 1000,
            migration_concurrency=int(os.environ.get("CONTROL_PLANE_MIGRATION_CONCURRENCY", "10")),
            service_account_rate_limit_max_attempts=int(
                os.environ.get("CONTROL_PLANE_SA_RATE_LIMIT_MAX_ATTEMPTS", "5")
            ),
            service_account_rate_limit_lockout_seconds=int(
                os.environ.get("CONTROL_PLANE_SA_RATE_LIMIT_LOCKOUT_SECONDS", "300")
            ),
            postgres_pool_min_size=int(os.environ.get("CONTROL_PLANE_PG_POOL_MIN_SIZE", "1")),
            postgres_pool_max_size=int(os.environ.get("CONTROL_PLANE_PG_POOL_MAX_SIZE", "5")),
            apply_schema_on_startup=_env_bool("CONTROL_PLANE_APPLY_SCHEMA", True),
            expose_docs=_env_bool("CONTROL_PLANE_EXPOSE_DOCS", False),
        )

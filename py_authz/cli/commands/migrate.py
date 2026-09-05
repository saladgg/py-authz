import json
import sys

from py_authz.cli.config import get_env
from py_authz.core.exceptions import ConfigurationError, ExternalServiceError
from py_authz.core.migrations_manager import MigrationManager
from py_authz.core.model_registry import InMemoryModelRegistry, ModelRegistry
from py_authz.core.tenant_store import InMemoryTenantStore, TenantStore


async def _build_backends(backend: str, conn: str | None) -> tuple[TenantStore, ModelRegistry]:
    """
    Construct the tenant store + model registry pair for `--backend`.

    `postgres` and `redis` share one connection string across both the
    tenant store and model registry — in practice they live in the same
    database/Redis instance. `memory` is for exercising this command
    without real infrastructure: a fresh in-memory store starts empty on
    every run, so it can never actually have tenants to find — it is not
    a usable production backend.
    """
    if backend == "memory":
        return InMemoryTenantStore(), InMemoryModelRegistry()

    if backend == "postgres":
        from py_authz.storage.postgres import PostgresModelRegistry, PostgresTenantStore

        dsn = conn or get_env("TENANT_STORE_CONN", required=True)
        tenant_store = PostgresTenantStore(dsn=dsn)
        model_registry = PostgresModelRegistry(dsn=dsn)
        await tenant_store.connect()
        await model_registry.connect()
        return tenant_store, model_registry

    if backend == "redis":
        from py_authz.storage.redis import RedisModelRegistry, RedisTenantStore

        url = conn or get_env("TENANT_STORE_CONN", required=True)
        return RedisTenantStore(url), RedisModelRegistry(url)

    raise ValueError(f"Unknown --backend: {backend!r} (expected memory, postgres, or redis)")


async def _close_backends(tenant_store: TenantStore, model_registry: ModelRegistry) -> None:
    """
    Release `tenant_store`/`model_registry`'s connections, if they have
    any to release.

    `_build_backends()` returns concrete classes with wildly different
    lifecycles (`InMemoryTenantStore` owns nothing; `PostgresTenantStore`/
    `RedisTenantStore` own a connection pool) — duck-typed via
    `hasattr(..., "close")` rather than importing every possible concrete
    type here. Previously nothing called this at all, leaking a Postgres
    pool (or, before REL2-8, being unable to close a Redis client even if
    it wanted to — `RedisTenantStore`/`RedisModelRegistry` had no
    `close()`) on every `--backend postgres`/`--backend redis` invocation.
    """
    for backend in (tenant_store, model_registry):
        close = getattr(backend, "close", None)
        if close is not None:
            await close()


async def migrate_command(
    *,
    api_url: str | None = None,
    backend: str = "memory",
    conn: str | None = None,
    tenant_ids: list[str] | None = None,
    dry_run: bool = False,
    yes: bool = False,
    json_output: bool = False,
) -> None:
    """
    Roll the current model out across tenants via `MigrationManager`.

    Args:
        api_url: OpenFGA API URL (falls back to `FGA_API_URL`).
        backend: where tenant→store mappings and model versions live —
            `memory` (testing only), `postgres`, or `redis`.
        conn: connection string for `backend` (Postgres DSN or Redis URL;
            falls back to `TENANT_STORE_CONN`).
        tenant_ids: migrate exactly these tenants; omit to migrate every
            tenant the backend's `list_tenant_ids()` reports (i.e.
            `--all-tenants`).
        dry_run: report which tenants would change without uploading or
            persisting anything (see REL2-10).
        yes: skip the confirmation prompt for `--all-tenants`. Required
            in a non-interactive context (no TTY) — see below.
        json_output: print one machine-readable JSON summary to stdout
            instead of the free-text, per-tenant lines below (see
            DX2-15) — meant for CI pipelines that want structured
            per-tenant results without line-parsing free text.
    """
    api_url = api_url or get_env("FGA_API_URL", required=True)

    tenant_store, model_registry = await _build_backends(backend, conn)

    try:
        all_tenants_mode = not tenant_ids
        ids = tenant_ids if tenant_ids else await tenant_store.list_tenant_ids()

        if not ids:
            if json_output:
                print(json.dumps({"tenants_found": 0, "succeeded": {}, "failed": {}}))
            else:
                print("No tenants found — nothing to migrate.")
            return

        if not dry_run and all_tenants_mode and not yes:
            # `--all-tenants` rolls a model change out to every tenant
            # this backend knows about — a genuinely destructive,
            # hard-to-undo operation with, until now, no preview and no
            # confirmation step (see REL2-10). Refuse to guess in a
            # non-interactive context (no TTY, e.g. a CI pipeline)
            # instead of blocking forever on `input()` — an automated
            # caller must pass `--yes` explicitly. Checked (and the
            # `MigrationManager` constructed) only once we know we're
            # actually going to need it — a decline/refusal here should
            # leave no side effects behind.
            if not sys.stdin.isatty():
                raise ConfigurationError(
                    "Refusing to migrate all tenants non-interactively without "
                    "--yes. Pass --dry-run first to preview, or --yes to confirm."
                )
            confirmation = input(
                f"About to migrate {len(ids)} tenant(s) to the current model. Continue? [y/N] "
            )
            if confirmation.strip().lower() not in ("y", "yes"):
                if json_output:
                    print(json.dumps({"aborted": True}))
                else:
                    print("Aborted.")
                return

        manager = MigrationManager(
            api_url=api_url,
            tenant_store=tenant_store,
            model_registry=model_registry,
        )

        if dry_run:
            changes = await manager.dry_run_all(ids)
            if json_output:
                print(json.dumps({"dry_run": True, "changes": changes}))
            else:
                for tenant_id, would_change in changes.items():
                    print(f"{tenant_id}: {'would migrate' if would_change else 'no change'}")
            return

        result = await manager.migrate_all(ids)

        if json_output:
            print(
                json.dumps(
                    {
                        "succeeded": result.succeeded,
                        "failed": {
                            tenant_id: str(error) for tenant_id, error in result.failed.items()
                        },
                    }
                )
            )
        else:
            for tenant_id, model_id in result.succeeded.items():
                print(f"{tenant_id}: {model_id}")

            for tenant_id, error in result.failed.items():
                print(f"{tenant_id}: FAILED - {error}", file=sys.stderr)

        if result.failed:
            raise ExternalServiceError(
                f"{len(result.failed)} of {len(ids)} tenant(s) failed to migrate"
            )
    finally:
        await _close_backends(tenant_store, model_registry)

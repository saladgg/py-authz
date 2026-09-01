from py_authz.cli.config import get_env
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


async def migrate_command(
    *,
    api_url: str | None = None,
    backend: str = "memory",
    conn: str | None = None,
    tenant_ids: list[str] | None = None,
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
    """
    api_url = api_url or get_env("FGA_API_URL", required=True)

    tenant_store, model_registry = await _build_backends(backend, conn)

    ids = tenant_ids if tenant_ids else await tenant_store.list_tenant_ids()

    if not ids:
        print("No tenants found — nothing to migrate.")
        return

    manager = MigrationManager(
        api_url=api_url,
        tenant_store=tenant_store,
        model_registry=model_registry,
    )
    results = await manager.migrate_all(ids)

    for tenant_id, model_id in results.items():
        print(f"{tenant_id}: {model_id}")

import json
from dataclasses import dataclass, field

import anyio

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.logging import logger
from py_authz.core.model_diff import ModelDiffer
from py_authz.core.model_registry import ModelRegistry
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_store import TenantStore
from py_authz.modeling.generator import generate_model


@dataclass
class MigrationBatchResult:
    """
    Result of `MigrationManager.migrate_all()`.

    A failure on one tenant no longer aborts the whole batch (see
    ARCH2-10) — `succeeded`/`failed` report every tenant's own outcome
    instead of the caller only ever seeing the first exception.
    """

    succeeded: dict[str, str] = field(default_factory=dict)
    failed: dict[str, Exception] = field(default_factory=dict)


@dataclass
class DryRunBatchResult:
    """
    Outcome of `MigrationManager.dry_run_batch()`: which tenants' models
    would change, and which tenants couldn't be checked (REL3-9).
    """

    would_change: dict[str, bool] = field(default_factory=dict)
    failed: dict[str, Exception] = field(default_factory=dict)


class MigrationManager:
    """
    Handles tenant-wide model migrations.
    """

    def __init__(
        self,
        *,
        api_url: str,
        tenant_store: TenantStore,
        model_registry: ModelRegistry,
    ):
        self.api_url = api_url
        self.tenant_store = tenant_store
        self.model_registry = model_registry

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    async def migrate_all(
        self, tenant_ids: list[str], *, concurrency: int = 10
    ) -> MigrationBatchResult:
        """
        Migrate all tenants to latest model, concurrently (bounded by
        `concurrency`).

        A failure on one tenant is captured on `MigrationBatchResult.
        failed` instead of aborting the rest of the batch or discarding
        results already computed for other tenants (see ARCH2-10) —
        mirroring `AuthzEngine.bulk_enforce()`'s same fix (DX2-1).
        """
        semaphore = anyio.Semaphore(concurrency)
        result = MigrationBatchResult()

        async def worker(tenant_id: str) -> None:
            async with semaphore:
                try:
                    result.succeeded[tenant_id] = await self.migrate_tenant(tenant_id)
                except Exception as exc:
                    result.failed[tenant_id] = exc
                    logger.exception(json.dumps({"event": "migration_failed", "tenant": tenant_id}))

        async with anyio.create_task_group() as tg:
            for tenant_id in tenant_ids:
                tg.start_soon(worker, tenant_id)

        return result

    async def migrate_tenant(self, tenant_id: str) -> str:
        """
        Migrate a single tenant safely.
        """

        logger.info(json.dumps({"event": "migration_start", "tenant": tenant_id}))

        store_id = await self.tenant_store.get(tenant_id)
        if not store_id:
            # `TenantNotFoundError` (an `AuthzError`), not a bare
            # `ValueError` — a typo'd `--tenant` is an anticipated user
            # mistake, and this is the exact exception type the rest of
            # the codebase already uses for "no such tenant" (see
            # `core/tenant_resolver.py`); it's also what lets the CLI's
            # top-level handler print a friendly message and a
            # categorized exit code instead of a raw traceback (ARCH2-5).
            raise TenantNotFoundError(f"Tenant not found: {tenant_id}")

        client = OpenFGAClient.for_tenant(api_url=self.api_url, store_id=store_id)

        try:
            syncer = ModelSync(client)

            # Sync (will diff automatically)
            new_model_id = await syncer.sync()

            # Whether anything actually changed is read from `syncer`'s
            # own real-time comparison against OpenFGA — not from a
            # separately-tracked "current model" read out of
            # `self.model_registry` beforehand. The latter used to be a
            # second, independent source of truth for the same fact: any
            # other code path that syncs a tenant's model (`Authz.
            # sync_model()`, `py-authz sync`) never updates
            # `model_registry`, so it could silently drift and report a
            # false "migration_success"/overwrite a value that hadn't
            # actually gone stale (see ARCH2-17). `model_registry` is now
            # purely a write-target here, never read back for this
            # decision.
            if not syncer.last_sync_changed:
                logger.info(
                    json.dumps(
                        {
                            "event": "migration_noop",
                            "tenant": tenant_id,
                            "model_id": new_model_id,
                        }
                    )
                )
                return new_model_id

            await self.model_registry.set(tenant_id, new_model_id)

            logger.info(
                json.dumps(
                    {
                        "event": "migration_success",
                        "tenant": tenant_id,
                        "model_id": new_model_id,
                    }
                )
            )
            return new_model_id
        finally:
            await client.aclose()

    async def dry_run_tenant(self, tenant_id: str) -> bool:
        """
        Report whether `migrate_tenant(tenant_id)` would change anything,
        without uploading a new model or persisting anything (see
        REL2-10 — backs `py-authz migrate --dry-run`).

        Returns:
            bool: True if the tenant's model would change.
        """
        store_id = await self.tenant_store.get(tenant_id)
        if not store_id:
            raise TenantNotFoundError(f"Tenant not found: {tenant_id}")

        client = OpenFGAClient.for_tenant(api_url=self.api_url, store_id=store_id)
        try:
            new_model = generate_model()
            current_model = await client.get_latest_model()
            return not (current_model and ModelDiffer.is_equal(new_model, current_model))
        finally:
            await client.aclose()

    async def dry_run_batch(
        self, tenant_ids: list[str], *, concurrency: int = 10
    ) -> DryRunBatchResult:
        """
        Concurrent `dry_run_tenant()` over many tenants, isolating each
        tenant's failure the same way `migrate_all()` does (ARCH2-10).
        Before REL3-9 one unreachable or stale tenant aborted the whole
        preview with a bare `ExceptionGroup` (a raw 500 from the control
        plane), discarding every other tenant's result.
        """
        semaphore = anyio.Semaphore(concurrency)
        result = DryRunBatchResult()

        async def worker(tenant_id: str) -> None:
            async with semaphore:
                try:
                    result.would_change[tenant_id] = await self.dry_run_tenant(tenant_id)
                except Exception as exc:
                    result.failed[tenant_id] = exc
                    logger.warning(
                        json.dumps({"event": "migration_dry_run_failed", "tenant": tenant_id})
                    )

        async with anyio.create_task_group() as tg:
            for tenant_id in tenant_ids:
                tg.start_soon(worker, tenant_id)

        return result

    async def dry_run_all(self, tenant_ids: list[str], *, concurrency: int = 10) -> dict[str, bool]:
        """
        Concurrent `dry_run_tenant()` over many tenants. Prefer
        `dry_run_batch()`, which reports per-tenant failures; this keeps
        its original all-or-nothing contract but raises the first
        tenant's actual error rather than a bare `ExceptionGroup`.
        """
        result = await self.dry_run_batch(tenant_ids, concurrency=concurrency)
        if result.failed:
            raise next(iter(result.failed.values()))
        return result.would_change

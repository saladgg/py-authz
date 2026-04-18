from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.logging import logger
from py_authz.core.model_registry import ModelRegistry
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_store import TenantStore


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

    async def migrate_all(self, tenant_ids: list[str]) -> dict[str, str]:
        """
        Migrate all tenants to latest model.

        Returns:
            dict: tenant_id → model_id
        """

        results = {}

        for tenant_id in tenant_ids:
            model_id = await self.migrate_tenant(tenant_id)
            results[tenant_id] = model_id

        return results

    async def migrate_tenant(self, tenant_id: str) -> str:
        """
        Migrate a single tenant safely.
        """

        logger.info(f"migration_start tenant={tenant_id}")

        store_id = await self.tenant_store.get(tenant_id)
        if not store_id:
            raise ValueError(f"Tenant not found: {tenant_id}")

        current_model = await self.model_registry.get(tenant_id)

        client = OpenFGAClient(
            api_url=self.api_url,
            store_id=store_id,
            model_id=None,
        )

        syncer = ModelSync(client)

        # Sync (will diff automatically)
        new_model_id = await syncer.sync()

        # If no change, skip update
        if current_model == new_model_id:
            logger.info(f"migration_noop tenant={tenant_id} model_id={current_model}")
            return current_model

        # Track version
        await self.model_registry.set(tenant_id, new_model_id)

        logger.info(f"migration_success tenant={tenant_id} model_id={new_model_id}")
        return new_model_id

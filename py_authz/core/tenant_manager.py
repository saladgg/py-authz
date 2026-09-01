from contextlib import asynccontextmanager

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.logging import logger
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_store import TenantStore


class TenantManager:
    """
    Handles tenant provisioning lifecycle.

    Responsibilities:
        - create store
        - sync model
        - persist mapping
    """

    def __init__(
        self,
        *,
        api_url: str,
        tenant_store: TenantStore,
        lock_manager=None,
    ):
        self.api_url = api_url
        self.tenant_store = tenant_store
        self.lock_manager = lock_manager

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    async def provision(self, tenant_id: str) -> str:
        """
        Provision a tenant.

        Returns:
            str: store_id
        """
        logger.info(f"provision_start tenant={tenant_id}")
        existing = await self.tenant_store.get(tenant_id)
        if existing:
            return existing

        async with self._provision_lock(tenant_id):
            # Re-check under lock: another caller may have provisioned
            # between our initial get() and lock acquisition.
            existing = await self.tenant_store.get(tenant_id)
            if existing:
                return existing

            client = OpenFGAClient(
                api_url=self.api_url,
                store_id=None,
                model_id=None,
            )
            # Assigned only once `create_store()` succeeds. Referencing an
            # unassigned `store_id` in the log line below used to raise
            # `UnboundLocalError` when `create_store()` itself failed,
            # masking the real (and far more actionable) exception.
            store_id: str | None = None
            try:
                store_id = await client.create_store(name=tenant_id)
                client.store_id = store_id

                syncer = ModelSync(client)
                await syncer.sync(force=True)

                await self.tenant_store.set(tenant_id, store_id)

                logger.info(f"provision_success tenant={tenant_id} store_id={store_id}")
                return store_id
            except Exception:
                logger.exception(f"provision_failed tenant={tenant_id} store_id={store_id}")
                raise
            finally:
                await client.aclose()

    @asynccontextmanager
    async def _provision_lock(self, tenant_id: str):
        if self.lock_manager is None:
            yield
            return

        async with self.lock_manager.lock(f"py_authz:provision:{tenant_id}"):
            yield

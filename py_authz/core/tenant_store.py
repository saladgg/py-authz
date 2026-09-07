from typing import Protocol


class TenantStore(Protocol):
    """
    Persistence layer for tenant → store mapping.
    """

    async def get(self, tenant_id: str) -> str | None: ...

    async def set(self, tenant_id: str, store_id: str) -> None: ...

    async def list_tenant_ids(self) -> list[str]: ...

    async def delete(self, tenant_id: str) -> None: ...

    # Note: `PostgresTenantStore`/`HybridTenantStore` additionally accept
    # optional `limit`/`offset` keyword arguments for pagination (see
    # REL2-17) — omitted from this Protocol since every real caller in
    # this repo (`MigrationManager`, `TenantManager`) enumerates the full
    # set with a bare `list_tenant_ids()` call, which every implementation
    # (including these extended ones) still supports unchanged.
    #
    # `delete()` (added for CP-4, backing `TenantManager.deprovision()`)
    # is idempotent — deleting a `tenant_id` with no mapping is a no-op,
    # not an error, matching `TenantManager.deprovision()`'s own
    # "deprovisioning an already-gone tenant" behavior.


# Temp class
class InMemoryTenantStore:
    def __init__(self):
        self._data: dict[str, str] = {}

    async def get(self, tenant_id: str) -> str | None:
        return self._data.get(tenant_id)

    async def set(self, tenant_id: str, store_id: str) -> None:
        self._data[tenant_id] = store_id

    async def list_tenant_ids(self, *, limit: int | None = None, offset: int = 0) -> list[str]:
        ids = sorted(self._data.keys())[offset:]
        return ids[:limit] if limit is not None else ids

    async def delete(self, tenant_id: str) -> None:
        self._data.pop(tenant_id, None)

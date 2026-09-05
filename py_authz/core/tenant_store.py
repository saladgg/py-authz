from typing import Protocol


class TenantStore(Protocol):
    """
    Persistence layer for tenant → store mapping.
    """

    async def get(self, tenant_id: str) -> str | None: ...

    async def set(self, tenant_id: str, store_id: str) -> None: ...

    async def list_tenant_ids(self) -> list[str]: ...

    # Note: `PostgresTenantStore`/`HybridTenantStore` additionally accept
    # optional `limit`/`offset` keyword arguments for pagination (see
    # REL2-17) — omitted from this Protocol since every real caller in
    # this repo (`MigrationManager`, `TenantManager`) enumerates the full
    # set with a bare `list_tenant_ids()` call, which every implementation
    # (including these extended ones) still supports unchanged.


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

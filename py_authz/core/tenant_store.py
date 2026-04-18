from typing import Protocol


class TenantStore(Protocol):
    """
    Persistence layer for tenant → store mapping.
    """

    async def get(self, tenant_id: str) -> str | None: ...

    async def set(self, tenant_id: str, store_id: str) -> None: ...


# Temp class
class InMemoryTenantStore:
    def __init__(self):
        self._data: dict[str, str] = {}

    async def get(self, tenant_id: str) -> str | None:
        return self._data.get(tenant_id)

    async def set(self, tenant_id: str, store_id: str) -> None:
        self._data[tenant_id] = store_id

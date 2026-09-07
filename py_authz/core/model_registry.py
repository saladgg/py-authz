from typing import Protocol


class ModelRegistry(Protocol):
    """
    Tracks model versions per tenant.
    """

    async def get(self, tenant_id: str) -> str | None: ...

    async def set(self, tenant_id: str, model_id: str) -> None: ...

    async def delete(self, tenant_id: str) -> None: ...

    # `delete()` (added for CP-4/CP-6) is idempotent, same contract as
    # `TenantStore.delete()`.


class InMemoryModelRegistry:
    def __init__(self):
        self._data: dict[str, str] = {}

    async def get(self, tenant_id: str) -> str | None:
        return self._data.get(tenant_id)

    async def set(self, tenant_id: str, model_id: str) -> None:
        self._data[tenant_id] = model_id

    async def delete(self, tenant_id: str) -> None:
        self._data.pop(tenant_id, None)

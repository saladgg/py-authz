from typing import Protocol


class TenantResolver(Protocol):
    """
    Resolves tenant_id → store_id
    """

    async def resolve(self, tenant_id: str) -> str: ...


class StaticTenantResolver:
    """
    Simple in-memory mapping.
    """

    def __init__(self, mapping: dict[str, str]):
        self.mapping = mapping

    async def resolve(self, tenant_id: str) -> str:
        if tenant_id not in self.mapping:
            raise ValueError(f"Unknown tenant: {tenant_id}")

        return self.mapping[tenant_id]

from typing import Protocol

from py_authz.core.exceptions import TenantNotFoundError


class TenantResolver(Protocol):
    """
    Resolves tenant_id → store_id.

    Implementations MUST raise `TenantNotFoundError` (not a bare
    `ValueError`/`KeyError`/etc.) when the tenant has no store mapping
    yet — that's the specific signal `MultiTenantAuthz.for_tenant()` uses
    to decide whether auto-provisioning is appropriate. Any other
    exception (a database timeout, a network error) propagates as a hard
    failure instead.
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
            raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

        return self.mapping[tenant_id]

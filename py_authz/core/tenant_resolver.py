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


class StoreBackedResolver:
    """
    Adapts any `TenantStore` (`get(tenant_id) -> str | None`) into a
    `TenantResolver`.

    `TenantStore` and `TenantResolver` are otherwise incompatible on the
    "not found" case — a store returns `None`, a resolver must raise
    `TenantNotFoundError` — so every multi-tenant consumer using a shared
    `TenantStore` behind `MultiTenantAuthz` ended up hand-writing this
    exact adapter (see `examples/06_multitenant.py`/
    `12_multitenant_fastapi.py`'s duplicated `_StoreBackedResolver`).
    Shipped once here instead (see ARCH2-14).

    Example:
        store = InMemoryTenantStore()  # or Postgres/Redis/Hybrid
        mt = MultiTenantAuthz(
            ...,
            tenant_resolver=StoreBackedResolver(store),
            tenant_manager=TenantManager(tenant_store=store, ...),
        )
    """

    def __init__(self, tenant_store):
        self.tenant_store = tenant_store

    async def resolve(self, tenant_id: str) -> str:
        store_id = await self.tenant_store.get(tenant_id)
        if store_id is None:
            raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")
        return store_id

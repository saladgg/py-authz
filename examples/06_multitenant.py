"""
06 — Multi-tenant: a store per tenant.

`MultiTenantAuthz` gives each tenant an isolated OpenFGA store. A request
comes in, you resolve its `tenant_id`, and `for_tenant()` returns an `Authz`
instance wired to that tenant's store. Instances are cached per-tenant.

Two roles:
    - `TenantResolver`  — maps tenant_id → store_id (how to find an existing
      store). This example uses a small store-backed resolver; in production
      you'd back it with Postgres/Redis.
    - `TenantManager`   — provisions a new store + syncs the model + persists
      the mapping atomically (optionally with a distributed lock). Pass it to
      `MultiTenantAuthz` to auto-provision on first access.

This script provisions two tenants, grants one tuple in each via
`Authz.grant()`, and shows that decisions are scoped to the calling tenant's
store.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples import models  # noqa: F401 — register models
from examples.models import Document
from py_authz import Identity
from py_authz.api import MultiTenantAuthz
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_store import InMemoryTenantStore

OPENFGA_URL = os.environ.get("FGA_API_URL", "http://localhost:8082")


async def main() -> None:
    # Shared persistence + provisioner. In production, swap InMemoryTenantStore
    # for a Postgres- or Redis-backed store so tenant mappings survive restarts.
    tenant_store = InMemoryTenantStore()
    manager = TenantManager(api_url=OPENFGA_URL, tenant_store=tenant_store)

    # Resolver reads from the same store the manager writes to.
    resolver = _StoreBackedResolver(tenant_store)

    mt = MultiTenantAuthz(
        api_url=OPENFGA_URL,
        model_id=None,  # per-tenant latest model is used
        tenant_resolver=resolver,
        tenant_manager=manager,  # auto-provision on unknown tenant
    )

    # First access triggers provisioning (create store + sync model).
    acme = await mt.for_tenant("acme")
    globex = await mt.for_tenant("globex")

    alice = Identity(id="user:alice")
    report = Document(id="report")

    # Seed different permissions in each tenant via the high-level API.
    await acme.grant(alice, "owner", report)
    await globex.grant(alice, "viewer", report)

    print("acme:   alice editor?", await acme.enforce("editor", alice, report.to_resource()))
    print("globex: alice editor?", await globex.enforce("editor", alice, report.to_resource()))
    print("globex: alice viewer?", await globex.enforce("viewer", alice, report.to_resource()))


class _StoreBackedResolver:
    """TenantResolver that reads from a TenantStore — raises
    `TenantNotFoundError` on unknown tenants so `MultiTenantAuthz` falls
    back to the manager (any other exception would propagate instead)."""

    def __init__(self, tenant_store: InMemoryTenantStore) -> None:
        self._store = tenant_store

    async def resolve(self, tenant_id: str) -> str:
        store_id = await self._store.get(tenant_id)
        if store_id is None:
            raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")
        return store_id


if __name__ == "__main__":
    asyncio.run(main())

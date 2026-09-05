"""
Regression coverage for DX2-6/DX2-11: `MultiTenantAuthz` composed with its
own real `StaticTenantResolver`/`TenantManager`/`MigrationManager` classes,
against a real OpenFGA instance.

`tests/api/test_multi_tenant.py` only ever exercises `MultiTenantAuthz`
against hand-rolled `FakeResolver`/`FakeManager` doubles — the 3-line
`FakeManager.provision()` stub there doesn't represent `TenantManager.
provision()`'s real logic (double-checked locking, `ModelSync` invocation,
cleanup-on-failure). `tests/core/test_tenant_manager.py`/
`test_migrations_manager.py` similarly both `monkeypatch.setattr(...,
"ModelSync", FakeModelSync)`, so the real `ModelSync(client).sync(...)` call
those managers make internally is never exercised against a real server
either. This is exactly the "mock both sides" pattern that caused REL-1
(`HybridTenantStore` + `RedisTenantStore`) and ARCH-1 (`ModelSync` reading a
field name that only exists on OpenFGA's *write* response, never its *list*
response) — see `tests/storage/test_hybrid.py`'s real-class composition
pattern, mirrored here.
"""

import pytest

from py_authz.api import MultiTenantAuthz
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.migrations_manager import MigrationManager
from py_authz.core.model_registry import InMemoryModelRegistry
from py_authz.core.tenant_manager import TenantManager
from py_authz.core.tenant_resolver import StaticTenantResolver
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry

from .conftest import requires_openfga


class LiveMTDocument(ResourceModel):
    type = "live_mt_document"

    owner = Relation("owner")
    viewer = Relation("viewer", union=["owner"])


registry.register(LiveMTDocument)


@pytest.fixture
def tenant_store() -> InMemoryTenantStore:
    """
    `InMemoryTenantStore` — the simplest real `TenantStore` implementation
    — is deliberately used here instead of `PostgresTenantStore`/
    `HybridTenantStore`. The point of this file is exercising
    `TenantManager`/`MigrationManager`/`MultiTenantAuthz`'s own real code
    paths against a real OpenFGA server; the tenant→store_id mapping's
    persistence backend is already covered independently (`test_hybrid.py`,
    `tests/live/test_postgres_storage_live.py`,
    `tests/live/test_redis_storage_live.py`).
    """
    return InMemoryTenantStore()


@pytest.fixture
def tenant_manager(fga_api_url, tenant_store) -> TenantManager:
    return TenantManager(api_url=fga_api_url, tenant_store=tenant_store)


@pytest.fixture
async def cleanup_stores(fga_api_url):
    """
    `TenantManager.provision()` creates real OpenFGA stores outside of
    `conftest.py`'s `live_client` fixture (which only manages the single
    store it creates for itself), so this file tracks and deletes whatever
    stores its own tests provision, via `OpenFGAClient.delete_store()`
    (ARCH2-8).
    """
    created: list[str] = []
    yield created

    if not created:
        return

    client = OpenFGAClient.for_tenant(api_url=fga_api_url)
    try:
        for store_id in created:
            await client.delete_store(store_id)
    finally:
        await client.aclose()


# ----------------------------------------------------------------------
# DX2-6: fresh-provision + idempotent-reuse, through the real
# `MultiTenantAuthz` -> `TenantManager` -> `ModelSync` composition.
# ----------------------------------------------------------------------


@requires_openfga
@pytest.mark.asyncio
async def test_for_tenant_provisions_real_tenant_and_enforces_correctly(
    tenant_manager, tenant_store, fga_api_url, cleanup_stores
):
    """
    Fresh-provision path: `StaticTenantResolver` has no mapping for this
    tenant yet, so `MultiTenantAuthz.for_tenant()` falls back to the real
    `TenantManager.provision()` — which creates a real OpenFGA store and
    runs a real `ModelSync(client).sync(force=True)` against it — and the
    resulting per-tenant `Authz` produces a real, correct authorization
    decision end to end.
    """
    resolver = StaticTenantResolver({})
    mt = MultiTenantAuthz(
        api_url=fga_api_url,
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=tenant_manager,
    )
    try:
        authz = await mt.for_tenant("acme")
        store_id = await tenant_store.get("acme")
        assert store_id is not None  # persisted by the real TenantManager
        cleanup_stores.append(store_id)

        alice = Identity(id="user:alice")
        doc = LiveMTDocument(id="doc-1")

        assert await authz.enforce("viewer", alice, doc.to_resource()) is False

        await authz.grant(alice, "owner", doc)

        assert await authz.enforce("viewer", alice, doc.to_resource()) is True
    finally:
        await mt.aclose()


@requires_openfga
@pytest.mark.asyncio
async def test_for_tenant_reuses_already_provisioned_tenant_without_reprovisioning(
    tenant_manager, tenant_store, fga_api_url, cleanup_stores
):
    """
    Idempotent-reuse path: `TenantManager.provision()`'s own
    double-checked "existing = await self.tenant_store.get(...)" early
    return must fire for real, against a real, already-persisted mapping
    — not just against `FakeManager`'s trivial stub.

    `StaticTenantResolver`'s mapping is fixed at construction and never
    learns about a tenant provisioned after it was built, so a *second*,
    independent `MultiTenantAuthz` instance (its own empty LRU cache, so
    it can't simply hit the outer cache) resolving the same `tenant_id`
    is guaranteed to fall through to `tenant_manager.provision()` again —
    exactly the path that must short-circuit without creating a second
    store.
    """
    resolver = StaticTenantResolver({})
    mt1 = MultiTenantAuthz(
        api_url=fga_api_url,
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=tenant_manager,
    )
    mt2 = MultiTenantAuthz(
        api_url=fga_api_url,
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=tenant_manager,
    )
    try:
        authz1 = await mt1.for_tenant("globex")
        first_store_id = await tenant_store.get("globex")
        cleanup_stores.append(first_store_id)

        authz2 = await mt2.for_tenant("globex")

        # Re-provisioning did not happen: the persisted mapping is
        # unchanged, and both engines point at the exact same real store.
        assert await tenant_store.get("globex") == first_store_id

        alice = Identity(id="user:alice")
        doc = LiveMTDocument(id="doc-2")

        await authz1.grant(alice, "owner", doc)
        assert await authz2.enforce("viewer", alice, doc.to_resource()) is True
    finally:
        await mt1.aclose()
        await mt2.aclose()


# ----------------------------------------------------------------------
# DX2-11: `MigrationManager.migrate_tenant()`'s real `ModelSync(client).
# sync()` call, run against the already-provisioned tenant above's real
# store.
# ----------------------------------------------------------------------


@requires_openfga
@pytest.mark.asyncio
async def test_migrate_tenant_runs_real_model_sync_and_reports_unchanged(
    tenant_manager, tenant_store, fga_api_url, cleanup_stores
):
    """
    `TenantManager.provision()` already ran `ModelSync(client).
    sync(force=True)` for this tenant, uploading the current model.
    Immediately migrating it again must be a genuine no-op against the
    real server: `ModelSync.last_sync_changed` (ARCH2-17) must correctly
    report `False`, and `MigrationManager.migrate_tenant()` must therefore
    NOT write to `model_registry` — this is exactly the field/response
    shape (`current_model["id"]`) that `FakeModelSync` never validates.
    """
    resolver = StaticTenantResolver({})
    mt = MultiTenantAuthz(
        api_url=fga_api_url,
        model_id=None,
        tenant_resolver=resolver,
        tenant_manager=tenant_manager,
    )
    try:
        await mt.for_tenant("initech")
        store_id = await tenant_store.get("initech")
        cleanup_stores.append(store_id)
    finally:
        await mt.aclose()

    model_registry = InMemoryModelRegistry()
    migration_manager = MigrationManager(
        api_url=fga_api_url,
        tenant_store=tenant_store,
        model_registry=model_registry,
    )

    model_id = await migration_manager.migrate_tenant("initech")

    # No real change -> migrate_tenant() never touches model_registry.
    assert await model_registry.get("initech") is None

    client = OpenFGAClient.for_tenant(api_url=fga_api_url, store_id=store_id)
    try:
        current = await client.get_latest_model()
        assert current is not None
        assert current["id"] == model_id
    finally:
        await client.aclose()


@requires_openfga
@pytest.mark.asyncio
async def test_migrate_tenant_raises_tenant_not_found_for_unknown_tenant(tenant_store, fga_api_url):
    migration_manager = MigrationManager(
        api_url=fga_api_url,
        tenant_store=tenant_store,
        model_registry=InMemoryModelRegistry(),
    )

    with pytest.raises(TenantNotFoundError):
        await migration_manager.migrate_tenant("no-such-tenant")

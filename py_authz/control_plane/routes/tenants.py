"""
Tenant CRUD (CP-4). Creating/listing tenants is a system-wide action
(`system#operator`+); viewing one tenant is that tenant's own
`tenant#auditor`+; deprovisioning accepts either that tenant's
`tenant#admin` or `system#owner` (see
`auth.require_tenant_admin_or_system_owner`'s docstring).
"""

from fastapi import APIRouter, Depends, Query

from py_authz.control_plane.auth import (
    CurrentPrincipal,
    require_system_role,
    require_tenant_admin_or_system_owner,
    require_tenant_role,
)
from py_authz.control_plane.deps import (
    get_model_registry,
    get_multi_tenant_authz,
    get_rbac_authz,
    get_redis_cache,
    get_tenant_manager,
    get_tenant_store,
)
from py_authz.control_plane.rbac_model import Tenant
from py_authz.control_plane.role_grants import delete_object_role_grants
from py_authz.control_plane.schemas import MAX_PAGE_SIZE, TenantCreateRequest
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.types import Resource

router = APIRouter(prefix="/tenants", tags=["tenants"])

_require_operator = require_system_role("operator", scope=Scope.TENANTS_WRITE)
_require_auditor_system = require_system_role("auditor", scope=Scope.TENANTS_READ)
_require_tenant_auditor = require_tenant_role("auditor", scope=Scope.TENANTS_READ)
_require_tenant_admin = require_tenant_role("admin", scope=Scope.TENANTS_WRITE)
_require_deprovision = require_tenant_admin_or_system_owner(scope=Scope.TENANTS_WRITE)


@router.post("", dependencies=[Depends(_require_operator)])
async def create_tenant(
    body: TenantCreateRequest,
    tenant_manager=Depends(get_tenant_manager),
    multi_tenant_authz=Depends(get_multi_tenant_authz),
) -> dict:
    """Provisions immediately (creates the real OpenFGA store + syncs
    the current model) rather than deferring to the async job system
    (CP-7) — provisioning a single tenant is fast (one store creation,
    one model sync), unlike an all-tenants migration."""
    store_id = await tenant_manager.provision(body.tenant_id)
    # Drop any instance cached against a previous store for this id
    # (REL3-4) — e.g. a tenant deprovisioned and recreated.
    await multi_tenant_authz.evict(body.tenant_id)
    return {"tenant_id": body.tenant_id, "store_id": store_id}


@router.get("", dependencies=[Depends(_require_auditor_system)])
async def list_tenants(
    limit: int = Query(100, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0),
    tenant_store=Depends(get_tenant_store),
) -> dict:
    ids = await tenant_store.list_tenant_ids(limit=limit, offset=offset)
    return {"items": ids}


@router.get("/{tenant_id}", dependencies=[Depends(_require_tenant_auditor)])
async def get_tenant(tenant_id: str, tenant_store=Depends(get_tenant_store)) -> dict:
    store_id = await tenant_store.get(tenant_id)
    if store_id is None:
        raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")
    return {"tenant_id": tenant_id, "store_id": store_id}


@router.post("/{tenant_id}/provision", dependencies=[Depends(_require_tenant_admin)])
async def provision_tenant(
    tenant_id: str,
    tenant_manager=Depends(get_tenant_manager),
    multi_tenant_authz=Depends(get_multi_tenant_authz),
) -> dict:
    """Idempotent — re-provisioning an already-provisioned tenant just
    returns its existing `store_id` (see `TenantManager.provision()`)."""
    store_id = await tenant_manager.provision(tenant_id)
    await multi_tenant_authz.evict(tenant_id)  # REL3-4
    return {"tenant_id": tenant_id, "store_id": store_id}


@router.delete("/{tenant_id}")
async def deprovision_tenant(
    tenant_id: str,
    principal: CurrentPrincipal = Depends(_require_deprovision),
    tenant_manager=Depends(get_tenant_manager),
    model_registry=Depends(get_model_registry),
    tenant_store=Depends(get_tenant_store),
    multi_tenant_authz=Depends(get_multi_tenant_authz),
    rbac_authz=Depends(get_rbac_authz),
    redis_cache=Depends(get_redis_cache),
) -> dict:
    """Deletes the real OpenFGA store and this tenant's `tenants`/
    `tenant_models` rows (see `TenantManager.deprovision()`, CP-4).
    Idempotent — deprovisioning an already-gone tenant is a no-op, not
    a 404, matching `TenantStore.delete()`'s contract.

    Then removes everything else tied to the tenant id, which used to
    outlive it:

    - every role grant on `tenant:<id>` in the RBAC store (SEC3-7) —
      tenant ids are human-chosen and get reused, and a new tenant under
      the same id used to inherit the old tenant's admins;
    - this process's cached `Authz` for it (REL3-4), bound to the store
      that was just deleted;
    - its cached decisions (namespaced by the old store id).
    """
    store_id = await tenant_store.get(tenant_id)
    await tenant_manager.deprovision(tenant_id, model_registry=model_registry)

    roles_removed = await delete_object_role_grants(
        rbac_authz,
        Resource(type=Tenant.type, id=tenant_id),
        reason=f"tenant {tenant_id} deprovisioned",
        actor=principal.identity,
    )
    await multi_tenant_authz.evict(tenant_id)
    cache_deleted = 0
    if store_id and redis_cache is not None:
        cache_deleted = await redis_cache.delete_by_prefix(f"{store_id}:")

    return {
        "status": "deprovisioned",
        "tenant_id": tenant_id,
        "roles_removed": roles_removed,
        "cache_entries_deleted": cache_deleted,
    }

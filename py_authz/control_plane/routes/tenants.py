"""
Tenant CRUD (CP-4). Creating/listing tenants is a system-wide action
(`system#operator`+); viewing one tenant is that tenant's own
`tenant#auditor`+; deprovisioning accepts either that tenant's
`tenant#admin` or `system#owner` (see
`auth.require_tenant_admin_or_system_owner`'s docstring).
"""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import (
    require_system_role,
    require_tenant_admin_or_system_owner,
    require_tenant_role,
)
from py_authz.control_plane.deps import get_model_registry, get_tenant_manager, get_tenant_store
from py_authz.control_plane.schemas import TenantCreateRequest
from py_authz.core.exceptions import TenantNotFoundError

router = APIRouter(prefix="/tenants", tags=["tenants"])

_require_operator = require_system_role("operator")
_require_auditor_system = require_system_role("auditor")
_require_tenant_auditor = require_tenant_role("auditor")
_require_tenant_admin = require_tenant_role("admin")
_require_deprovision = require_tenant_admin_or_system_owner()


@router.post("", dependencies=[Depends(_require_operator)])
async def create_tenant(
    body: TenantCreateRequest, tenant_manager=Depends(get_tenant_manager)
) -> dict:
    """Provisions immediately (creates the real OpenFGA store + syncs
    the current model) rather than deferring to the async job system
    (CP-7) — provisioning a single tenant is fast (one store creation,
    one model sync), unlike an all-tenants migration."""
    store_id = await tenant_manager.provision(body.tenant_id)
    return {"tenant_id": body.tenant_id, "store_id": store_id}


@router.get("", dependencies=[Depends(_require_auditor_system)])
async def list_tenants(
    limit: int = 100, offset: int = 0, tenant_store=Depends(get_tenant_store)
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
async def provision_tenant(tenant_id: str, tenant_manager=Depends(get_tenant_manager)) -> dict:
    """Idempotent — re-provisioning an already-provisioned tenant just
    returns its existing `store_id` (see `TenantManager.provision()`)."""
    store_id = await tenant_manager.provision(tenant_id)
    return {"tenant_id": tenant_id, "store_id": store_id}


@router.delete("/{tenant_id}", dependencies=[Depends(_require_deprovision)])
async def deprovision_tenant(
    tenant_id: str,
    tenant_manager=Depends(get_tenant_manager),
    model_registry=Depends(get_model_registry),
) -> dict:
    """Deletes the real OpenFGA store and this tenant's `tenants`/
    `tenant_models` rows (see `TenantManager.deprovision()`, CP-4).
    Idempotent — deprovisioning an already-gone tenant is a no-op, not
    a 404, matching `TenantStore.delete()`'s contract."""
    await tenant_manager.deprovision(tenant_id, model_registry=model_registry)
    return {"status": "deprovisioned", "tenant_id": tenant_id}

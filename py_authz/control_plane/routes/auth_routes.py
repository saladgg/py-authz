"""GET /auth/me (CP-2)."""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import (
    CurrentPrincipal,
    effective_system_role,
    get_current_principal,
)
from py_authz.control_plane.deps import get_rbac_authz

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/me")
async def get_me(
    principal: CurrentPrincipal = Depends(get_current_principal),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    """
    The caller's own identity + effective system-scope role. Per-tenant
    roles aren't enumerated here (that would mean walking every known
    tenant) — check a specific tenant via that tenant's own routes, which
    already 403 cleanly if the caller lacks access.
    """
    role = None
    if principal.kind == "operator":
        role = await effective_system_role(rbac_authz, principal.identity)

    return {
        "id": principal.identity.id,
        "kind": principal.kind,
        "scopes": list(principal.scopes) if principal.kind == "service_account" else None,
        "system_role": role,
    }

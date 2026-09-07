"""
Tuple read API + manual grant/revoke (CP-8). `Authz.grant`/`revoke` are
reused unchanged — cache invalidation and audit/metrics recording are
already handled there (see `record_write`); this route's only job is
requiring the mandatory `reason` field and passing the acting operator
through as `actor`.
"""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import CurrentPrincipal, require_tenant_role
from py_authz.control_plane.deps import get_multi_tenant_authz
from py_authz.control_plane.schemas import GrantRevokeRequest
from py_authz.core.types import Identity

router = APIRouter(prefix="/tenants/{tenant_id}", tags=["tuples"])

_require_auditor = require_tenant_role("auditor")
_require_admin = require_tenant_role("admin")


@router.get("/tuples", dependencies=[Depends(_require_auditor)])
async def list_tuples(
    tenant_id: str,
    user: str | None = None,
    relation: str | None = None,
    object: str | None = None,
    page_size: int | None = None,
    continuation_token: str | None = None,
    multi_tenant_authz=Depends(get_multi_tenant_authz),
) -> dict:
    """
    "Who has `viewer` on `document:roadmap`" (`relation`+`object`, no
    `user`) or "what does `user:alice` hold" (`user` only) — the
    relationship-explorer building block. At least one filter is
    strongly recommended; an empty filter returns the whole store.
    """
    authz = await multi_tenant_authz.for_tenant(tenant_id)
    return await authz.read_tuples(
        user=user,
        relation=relation,
        object=object,
        page_size=page_size,
        continuation_token=continuation_token,
    )


@router.post("/grants", dependencies=[Depends(_require_admin)])
async def grant_tuple(
    tenant_id: str,
    body: GrantRevokeRequest,
    principal: CurrentPrincipal = Depends(_require_admin),
    multi_tenant_authz=Depends(get_multi_tenant_authz),
) -> dict:
    authz = await multi_tenant_authz.for_tenant(tenant_id)
    await authz.grant(
        Identity(id=body.user),
        body.relation,
        body.object,
        reason=body.reason,
        actor=principal.identity,
    )
    return {
        "status": "granted",
        "user": body.user,
        "relation": body.relation,
        "object": body.object.to_fga_object(),
    }


@router.post("/revokes", dependencies=[Depends(_require_admin)])
async def revoke_tuple(
    tenant_id: str,
    body: GrantRevokeRequest,
    principal: CurrentPrincipal = Depends(_require_admin),
    multi_tenant_authz=Depends(get_multi_tenant_authz),
) -> dict:
    authz = await multi_tenant_authz.for_tenant(tenant_id)
    await authz.revoke(
        Identity(id=body.user),
        body.relation,
        body.object,
        reason=body.reason,
        actor=principal.identity,
    )
    return {
        "status": "revoked",
        "user": body.user,
        "relation": body.relation,
        "object": body.object.to_fga_object(),
    }

"""
Operators & role assignment — the backend counterpart to the
"Operators & Roles" screen the architecture doc's §2.4 describes (backed
by "the dogfooded RBAC store, §2.5"), needed for CP-13's frontend build.
Not itself one of the audit-derived `CP-1`..`CP-10` findings in
`09_control_panel_todos.md` — it's additive surface the frontend build
(Tier 3) needs and the narrative doc already specifies the shape of but
the todos file never separately enumerated as a route to build (its
Tier-0 items cover *authenticating* as an operator and the RBAC model
itself, not a management UI for assigning roles to other operators).

Reuses `Authz.grant`/`revoke`/`can`/`read_tuples` against the RBAC store
unchanged — same principle as every other route in this package.
"""

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from py_authz.control_plane.auth import CurrentPrincipal, get_current_principal
from py_authz.control_plane.deps import get_operator_store, get_rbac_authz
from py_authz.control_plane.operators import OperatorStore
from py_authz.control_plane.rbac_model import ROLE_CHAIN, SYSTEM_OBJECT_ID, System, Tenant
from py_authz.core.exceptions import AuthorizationDenied, InvalidAuthzRequest
from py_authz.core.types import Identity, Resource

router = APIRouter(prefix="/operators", tags=["operators"])


class RoleAssignment(BaseModel):
    #: Bare subject (the verified OIDC `sub`, no `"user:"` prefix — that's
    #: added here, matching `OIDCJWTValidator.to_identity()`'s own
    #: convention) to grant/revoke a role for.
    subject: str
    scope: str  # "system" | "tenant"
    tenant_id: str | None = None
    role: str


def _resource_for(assignment: RoleAssignment) -> Resource:
    if assignment.scope == "system":
        return Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    if assignment.scope == "tenant":
        if not assignment.tenant_id:
            raise InvalidAuthzRequest("tenant_id is required when scope='tenant'")
        return Resource(type=Tenant.type, id=assignment.tenant_id)
    raise InvalidAuthzRequest(f"Unknown scope {assignment.scope!r} — must be 'system' or 'tenant'")


async def _require_system_auditor(principal: CurrentPrincipal, rbac_authz) -> None:
    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    if not await rbac_authz.can("auditor", principal.identity, system_resource):
        raise AuthorizationDenied(f"{principal.identity.id!r} does not hold system#auditor")


async def _require_role_management(
    principal: CurrentPrincipal, assignment: RoleAssignment, rbac_authz
) -> None:
    """
    Granting/revoking a *system*-scoped role requires `system#owner` —
    the most sensitive action in this whole API, since it can grant
    itself (or anyone else) more roles. Granting/revoking a *tenant*-
    scoped role accepts that tenant's own `tenant#admin`, or
    `system#owner` — same OR as `require_tenant_admin_or_system_owner`
    (`auth.py`), reimplemented inline here since this check's target
    resource comes from the request body, not a path/query param the
    existing dependency factories read from.
    """
    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)

    if assignment.scope == "system":
        if not await rbac_authz.can("owner", principal.identity, system_resource):
            raise AuthorizationDenied(f"{principal.identity.id!r} does not hold system#owner")
        return

    tenant_resource = _resource_for(assignment)
    if await rbac_authz.can("admin", principal.identity, tenant_resource):
        return
    if await rbac_authz.can("owner", principal.identity, system_resource):
        return
    raise AuthorizationDenied(
        f"{principal.identity.id!r} holds neither tenant:{assignment.tenant_id}#admin "
        "nor system#owner"
    )


@router.get("")
async def list_operators(
    principal: CurrentPrincipal = Depends(get_current_principal),
    operator_store: OperatorStore = Depends(get_operator_store),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    """Every subject that has ever logged in (see `OperatorStore.
    record_login()`) — the pool a role can be assigned to. Doesn't itself
    say what role each one holds; see `GET /operators/roles` for that."""
    await _require_system_auditor(principal, rbac_authz)
    operators = await operator_store.list()
    return {
        "items": [
            {
                "id": op.id,
                "subject": op.subject,
                "email": op.email,
                "created_at": op.created_at.isoformat(),
            }
            for op in operators
        ]
    }


@router.get("/roles")
async def list_roles(
    scope: str,
    tenant_id: str | None = None,
    principal: CurrentPrincipal = Depends(get_current_principal),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    """
    Every `(subject, role)` pair currently granted at this scope — reads
    the RBAC store's own tuples directly (`Authz.read_tuples()`) rather
    than tracking a separate copy of "who has what role" anywhere else.
    """
    assignment = RoleAssignment(subject="", scope=scope, tenant_id=tenant_id, role="")
    resource = _resource_for(assignment)

    if scope == "system":
        await _require_system_auditor(principal, rbac_authz)
    else:
        system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
        if not (
            await rbac_authz.can("auditor", principal.identity, resource)
            or await rbac_authz.can("owner", principal.identity, system_resource)
        ):
            raise AuthorizationDenied(
                f"{principal.identity.id!r} holds neither tenant:{tenant_id}#auditor "
                "nor system#owner"
            )

    result = await rbac_authz.read_tuples(object=resource.to_fga_object())
    return {
        "items": [
            {"subject": t["user"], "role": t["relation"]}
            for t in result["tuples"]
            if t["relation"] in ROLE_CHAIN
        ]
    }


@router.post("/roles")
async def grant_role(
    body: RoleAssignment,
    principal: CurrentPrincipal = Depends(get_current_principal),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    if body.role not in ROLE_CHAIN:
        raise InvalidAuthzRequest(f"Unknown role {body.role!r} — must be one of {ROLE_CHAIN}")

    await _require_role_management(principal, body, rbac_authz)
    resource = _resource_for(body)
    target = Identity(id=f"user:{body.subject}")

    await rbac_authz.grant(
        target,
        body.role,
        resource,
        reason=f"role grant by {principal.identity.id}",
        actor=principal.identity,
    )
    return {
        "status": "granted",
        "subject": body.subject,
        "role": body.role,
        "scope": body.scope,
        "tenant_id": body.tenant_id,
    }


@router.delete("/roles")
async def revoke_role(
    body: RoleAssignment,
    principal: CurrentPrincipal = Depends(get_current_principal),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    await _require_role_management(principal, body, rbac_authz)
    resource = _resource_for(body)
    target = Identity(id=f"user:{body.subject}")

    await rbac_authz.revoke(
        target,
        body.role,
        resource,
        reason=f"role revoke by {principal.identity.id}",
        actor=principal.identity,
    )
    return {
        "status": "revoked",
        "subject": body.subject,
        "role": body.role,
        "scope": body.scope,
        "tenant_id": body.tenant_id,
    }

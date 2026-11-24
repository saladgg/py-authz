"""
Service accounts: create/list/revoke/rotate (CP-3). `system#admin` (or
higher) only — service accounts are a system-wide, not per-tenant,
concept. `secret`/`secret_hash` never appear in a list response; only a
create/rotate response carries the plaintext `secret`, and only once.

Rotating or revoking an account additionally requires the caller to
*dominate* it (SEC3-2): to already hold, on every object the account has
a role on, a role at least as privileged. Rotation hands the caller the
account's new secret — i.e. the ability to act as it — so without this a
`system#admin` could rotate an owner-held account and use its secret to
make themselves `system#owner`. Revoking also deletes the account's RBAC
grants, so nothing lingers against its (never-reused) principal id.
"""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import CurrentPrincipal, require_system_role
from py_authz.control_plane.deps import get_rbac_authz, get_service_account_store
from py_authz.control_plane.rbac_model import service_account_principal
from py_authz.control_plane.role_grants import direct_role_grants, dominates
from py_authz.control_plane.schemas import ServiceAccountCreateRequest
from py_authz.control_plane.scopes import Scope
from py_authz.control_plane.service_accounts import ServiceAccount, ServiceAccountStore
from py_authz.core.exceptions import AuthorizationDenied
from py_authz.core.types import Identity

router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])

# Defined once and reused as the exact same callable across a route's
# `dependencies=[...]` and any parameter that also needs the resolved
# `CurrentPrincipal` — FastAPI dedupes a dependency within one request by
# object identity, so two `Depends(require_system_role("admin"))` calls
# built from two *separate* `require_system_role("admin")` invocations
# would otherwise run (and RBAC-check) twice.
_require_admin = require_system_role("admin", scope=Scope.SERVICE_ACCOUNTS_WRITE)
_require_auditor = require_system_role("auditor", scope=Scope.SERVICE_ACCOUNTS_READ)


def _public(account: ServiceAccount) -> dict:
    """Every field except `secret_hash` — never serialize that, even to
    an authenticated caller."""
    return {
        "id": account.id,
        "name": account.name,
        "description": account.description,
        "scopes": account.scopes,
        "created_by": account.created_by,
        "created_at": account.created_at.isoformat(),
        "last_used_at": account.last_used_at.isoformat() if account.last_used_at else None,
        "revoked_at": account.revoked_at.isoformat() if account.revoked_at else None,
    }


@router.post("")
async def create_service_account(
    body: ServiceAccountCreateRequest,
    principal: CurrentPrincipal = Depends(_require_admin),
    store: ServiceAccountStore = Depends(get_service_account_store),
) -> dict:
    account, secret = await store.create(
        name=body.name,
        description=body.description,
        scopes=sorted({s.value for s in body.scopes}),
        created_by=principal.identity.id,
    )
    return {**_public(account), "secret": secret}


@router.get("", dependencies=[Depends(_require_auditor)])
async def list_service_accounts(
    store: ServiceAccountStore = Depends(get_service_account_store),
) -> dict:
    accounts = await store.list()
    return {"items": [_public(a) for a in accounts]}


async def _require_dominates(rbac_authz, principal: CurrentPrincipal, account_id: str):
    grants = await direct_role_grants(rbac_authz, service_account_principal(account_id))
    if not await dominates(rbac_authz, principal.identity, grants):
        raise AuthorizationDenied(
            f"{principal.identity.id!r} does not hold every role service account "
            f"{account_id!r} holds — rotating or revoking it would be a privilege escalation"
        )
    return grants


@router.delete("/{account_id}")
async def revoke_service_account(
    account_id: str,
    principal: CurrentPrincipal = Depends(_require_admin),
    store: ServiceAccountStore = Depends(get_service_account_store),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    grants = await _require_dominates(rbac_authz, principal, account_id)
    await store.revoke(account_id)

    sa_identity = Identity(id=service_account_principal(account_id))
    for grant in grants:
        await rbac_authz.revoke(
            sa_identity,
            grant.role,
            grant.resource,
            reason=f"service account {account_id} revoked",
            actor=principal.identity,
        )
    return {"status": "revoked", "id": account_id, "roles_removed": len(grants)}


@router.post("/{account_id}/rotate")
async def rotate_service_account(
    account_id: str,
    principal: CurrentPrincipal = Depends(_require_admin),
    store: ServiceAccountStore = Depends(get_service_account_store),
    rbac_authz=Depends(get_rbac_authz),
) -> dict:
    await _require_dominates(rbac_authz, principal, account_id)
    account, secret = await store.rotate(account_id)
    return {**_public(account), "secret": secret}

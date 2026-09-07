"""
Service accounts: create/list/revoke/rotate (CP-3). `system#admin` (or
higher) only — service accounts are a system-wide, not per-tenant,
concept. `secret`/`secret_hash` never appear in a list response; only a
create/rotate response carries the plaintext `secret`, and only once.
"""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import CurrentPrincipal, require_system_role
from py_authz.control_plane.deps import get_service_account_store
from py_authz.control_plane.schemas import ServiceAccountCreateRequest
from py_authz.control_plane.service_accounts import ServiceAccount, ServiceAccountStore

router = APIRouter(prefix="/service-accounts", tags=["service-accounts"])

# Defined once and reused as the exact same callable across a route's
# `dependencies=[...]` and any parameter that also needs the resolved
# `CurrentPrincipal` — FastAPI dedupes a dependency within one request by
# object identity, so two `Depends(require_system_role("admin"))` calls
# built from two *separate* `require_system_role("admin")` invocations
# would otherwise run (and RBAC-check) twice.
_require_admin = require_system_role("admin")
_require_auditor = require_system_role("auditor")


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
        scopes=body.scopes,
        created_by=principal.identity.id,
    )
    return {**_public(account), "secret": secret}


@router.get("", dependencies=[Depends(_require_auditor)])
async def list_service_accounts(
    store: ServiceAccountStore = Depends(get_service_account_store),
) -> dict:
    accounts = await store.list()
    return {"items": [_public(a) for a in accounts]}


@router.delete("/{account_id}", dependencies=[Depends(_require_admin)])
async def revoke_service_account(
    account_id: str, store: ServiceAccountStore = Depends(get_service_account_store)
) -> dict:
    await store.revoke(account_id)
    return {"status": "revoked", "id": account_id}


@router.post("/{account_id}/rotate", dependencies=[Depends(_require_admin)])
async def rotate_service_account(
    account_id: str, store: ServiceAccountStore = Depends(get_service_account_store)
) -> dict:
    account, secret = await store.rotate(account_id)
    return {**_public(account), "secret": secret}

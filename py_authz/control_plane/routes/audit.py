"""GET /audit-logs (CP-5)."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from py_authz.audit.postgres import PostgresAuditQuery, decode_cursor, encode_cursor
from py_authz.control_plane.auth import require_system_or_tenant_role_from_query
from py_authz.control_plane.deps import get_audit_query, get_tenant_store
from py_authz.control_plane.schemas import MAX_PAGE_SIZE
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import InvalidAuthzRequest

router = APIRouter(tags=["audit"])

_require_auditor = require_system_or_tenant_role_from_query("auditor", scope=Scope.AUDIT_READ)


@router.get("/audit-logs", dependencies=[Depends(_require_auditor)])
async def list_audit_logs(
    tenant_id: str | None = None,
    user_id: str | None = None,
    action: str | None = None,
    resource: str | None = None,
    allowed: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(50, ge=1, le=MAX_PAGE_SIZE),
    offset: int = Query(0, ge=0),
    cursor: str | None = None,
    audit_query: PostgresAuditQuery = Depends(get_audit_query),
    tenant_store=Depends(get_tenant_store),
) -> dict:
    """
    Filters map onto `PostgresAuditQuery.query()`'s (every filter ANDed).
    Omitting `tenant_id` requires a system-scoped role (see
    `require_system_or_tenant_role_from_query`), since it returns every
    tenant's events.

    Since ARCH3-16, `audit_logs.tenant_id` holds the tenant id, so a
    deprovisioned tenant's history is still found by its id. Rows written
    before migration 0009 held the store id there; they're matched through
    the tenant's current store id, and echoed back with the requested
    `tenant_id`.

    Paging (REL3-15): pass the previous page's `next_cursor` as `cursor`.
    `next_cursor` is `null` on a short page. `offset` still works (not
    together with `cursor`) but costs more the deeper it goes.
    """
    if cursor is not None and offset:
        raise InvalidAuthzRequest("Pass either cursor or offset, not both")
    before = decode_cursor(cursor) if cursor is not None else None

    legacy_store_id = None
    if tenant_id is not None:
        legacy_store_id = await tenant_store.get(tenant_id)

    items = await audit_query.query(
        tenant_id=tenant_id,
        legacy_store_id=legacy_store_id,
        user_id=user_id,
        action=action,
        resource=resource,
        allowed=allowed,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
        before=before,
    )
    next_cursor = (
        encode_cursor(items[-1]["timestamp"], items[-1]["id"]) if len(items) == limit else None
    )
    for item in items:
        item["timestamp"] = item["timestamp"].isoformat()
        if tenant_id is not None:
            item["tenant_id"] = tenant_id
    return {"items": items, "next_cursor": next_cursor}

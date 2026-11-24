"""GET /audit-logs (CP-5)."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query

from py_authz.audit.postgres import PostgresAuditQuery
from py_authz.control_plane.auth import require_system_or_tenant_role_from_query
from py_authz.control_plane.deps import get_audit_query, get_tenant_store
from py_authz.control_plane.schemas import MAX_PAGE_SIZE
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import TenantNotFoundError

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
    audit_query: PostgresAuditQuery = Depends(get_audit_query),
    tenant_store=Depends(get_tenant_store),
) -> dict:
    """
    Filters map directly onto `PostgresAuditQuery.query()`'s own — see
    its docstring for exact semantics (limit/offset pagination, every
    filter ANDed). Omitting `tenant_id` requires a system-scoped role
    (see `require_system_or_tenant_role_from_query`) since it returns
    every tenant's events.

    `audit_logs.tenant_id` is actually populated from
    `AuthzEngine.fga_client.store_id` (see `core/enforcement.py`'s
    `record_write`/`_audit_decision`) — the OpenFGA store id, not the
    human-readable `tenant_id` this API and every other route use
    everywhere else. A caller filtering by the human-readable
    `tenant_id` would otherwise silently get zero rows back forever, no
    matter how many events that tenant has — resolved here via
    `tenant_store` before querying, the same way `routes/tuples.py`
    resolves it via `MultiTenantAuthz.for_tenant()`. When a `tenant_id`
    filter is given, every returned row's `tenant_id` is echoed back as
    the human-readable one requested (they're guaranteed to match) rather
    than the raw store id a caller has no other reason to know.
    """
    store_id_filter = None
    if tenant_id is not None:
        store_id_filter = await tenant_store.get(tenant_id)
        if store_id_filter is None:
            raise TenantNotFoundError(f"Unknown tenant: {tenant_id}")

    items = await audit_query.query(
        tenant_id=store_id_filter,
        user_id=user_id,
        action=action,
        resource=resource,
        allowed=allowed,
        since=since,
        until=until,
        limit=limit,
        offset=offset,
    )
    for item in items:
        item["timestamp"] = item["timestamp"].isoformat()
        if tenant_id is not None:
            item["tenant_id"] = tenant_id
    return {"items": items}

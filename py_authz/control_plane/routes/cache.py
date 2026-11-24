"""Cache stats + bulk invalidate (CP-9). `RedisCache`-specific — a
deployment with no Redis configured gets a 503 from these routes, not a
crash (see `deps.get_redis_cache`)."""

from fastapi import APIRouter, Depends, HTTPException

from py_authz.cache.redis import RedisCache
from py_authz.control_plane.auth import require_system_role
from py_authz.control_plane.deps import get_redis_cache, get_tenant_store
from py_authz.control_plane.schemas import CacheInvalidateRequest
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import InvalidAuthzRequest, TenantNotFoundError
from py_authz.core.types import AuthzRequest

router = APIRouter(prefix="/cache", tags=["cache"])

_require_auditor = require_system_role("auditor", scope=Scope.CACHE_READ)
_require_operator = require_system_role("operator", scope=Scope.CACHE_WRITE)


def _require_cache(cache: RedisCache | None) -> RedisCache:
    if cache is None:
        raise HTTPException(status_code=503, detail="No Redis cache configured for this deployment")
    return cache


@router.get("/stats", dependencies=[Depends(_require_auditor)])
async def cache_stats(cache: RedisCache | None = Depends(get_redis_cache)) -> dict:
    cache = _require_cache(cache)
    return {"key_count": await cache.count_keys()}


@router.post("/invalidate", dependencies=[Depends(_require_operator)])
async def invalidate_cache(
    body: CacheInvalidateRequest,
    cache: RedisCache | None = Depends(get_redis_cache),
    tenant_store=Depends(get_tenant_store),
) -> dict:
    """
    Cached decisions for a tenant live under that tenant engine's
    `cache_namespace`, which `MultiTenantAuthz` sets to the tenant's
    OpenFGA **store id** — not the human-readable `tenant_id` this API
    takes. Until SEC3-6 this route matched on `tenant_id` directly, so
    "invalidate tenant acme" reported success and deleted nothing (stale
    allow decisions kept being served until TTL). It now resolves the
    store id first (404 on an unknown tenant, same as the audit route)
    and deletes by key *prefix*, so it can't over-match another tenant's
    keys either.
    """
    cache = _require_cache(cache)

    if body.key:
        await cache.delete(body.key)
        return {"status": "invalidated", "mode": "key"}

    store_id = None
    if body.tenant_id:
        store_id = await tenant_store.get(body.tenant_id)
        if store_id is None:
            raise TenantNotFoundError(f"Unknown tenant: {body.tenant_id}")

    if body.user_id:
        identity_prefix = AuthzRequest.identity_prefix(body.user_id)
        if store_id:
            deleted = await cache.delete_by_prefix(f"{store_id}:{identity_prefix}")
        else:
            # Every tenant (and any un-namespaced engine): the identity
            # prefix can follow any namespace, so this one is a fragment
            # match — still glob-escaped by `delete_by_fragment()`.
            deleted = await cache.delete_by_fragment(identity_prefix)
        return {"status": "invalidated", "mode": "user", "deleted": deleted}

    if store_id:
        deleted = await cache.delete_by_prefix(f"{store_id}:")
        return {"status": "invalidated", "mode": "tenant", "deleted": deleted}

    raise InvalidAuthzRequest("One of key, user_id, or tenant_id is required")

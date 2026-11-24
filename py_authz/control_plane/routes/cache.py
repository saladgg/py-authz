"""Cache stats + bulk invalidate (CP-9). `RedisCache`-specific — a
deployment with no Redis configured gets a 503 from these routes, not a
crash (see `deps.get_redis_cache`)."""

from fastapi import APIRouter, Depends, HTTPException

from py_authz.cache.redis import RedisCache
from py_authz.control_plane.auth import require_system_role
from py_authz.control_plane.deps import get_redis_cache
from py_authz.control_plane.schemas import CacheInvalidateRequest
from py_authz.control_plane.scopes import Scope
from py_authz.core.exceptions import InvalidAuthzRequest
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
    body: CacheInvalidateRequest, cache: RedisCache | None = Depends(get_redis_cache)
) -> dict:
    cache = _require_cache(cache)

    if body.key:
        await cache.delete(body.key)
        return {"status": "invalidated", "mode": "key"}

    if body.user_id:
        fragment = AuthzRequest.identity_prefix(body.user_id)
        if body.tenant_id:
            fragment = f"{body.tenant_id}:{fragment}"
        deleted = await cache.delete_by_fragment(fragment)
        return {"status": "invalidated", "mode": "user", "deleted": deleted}

    if body.tenant_id:
        deleted = await cache.delete_by_fragment(f"{body.tenant_id}:")
        return {"status": "invalidated", "mode": "tenant", "deleted": deleted}

    raise InvalidAuthzRequest("One of key, user_id, or tenant_id is required")

import json
import logging

logger = logging.getLogger(__name__)


class HybridTenantStore:
    """
    Redis (cache) + Postgres (source of truth).

    Both `pg_store` and `redis_store` are expected to conform to the
    `TenantStore`-shaped contract: `get(tenant_id) -> str | None` and
    `set(tenant_id, store_id, ex=None) -> None` — i.e. they already
    return/accept plain `str`, not raw bytes. `RedisTenantStore`/
    `RedisModelRegistry` (`storage/redis.py`) satisfy this; a bare
    `redis.asyncio.Redis` client does not (it returns raw bytes from
    `get()` and its `set()`, while it does accept `ex`, isn't meant to be
    handed to this class directly) and should not be passed here.

    Redis is treated as advisory, never load-bearing: any exception from
    `redis_store.get()`/`.set()` is caught, logged, and the call degrades
    to Postgres alone (see REL2-2) — a Redis outage must never make tenant
    resolution *less* available than a bare `PostgresTenantStore` would
    have been on its own.
    """

    def __init__(self, pg_store, redis_store):
        self.pg = pg_store
        self.redis = redis_store

    async def get(self, tenant_id: str):
        cached = await self._redis_get(tenant_id)
        if cached:
            return cached

        store_id = await self.pg.get(tenant_id)

        if store_id:
            await self._redis_set(tenant_id, store_id)

        return store_id

    async def set(self, tenant_id: str, store_id: str):
        await self.pg.set(tenant_id, store_id)
        await self._redis_set(tenant_id, store_id)

    async def delete(self, tenant_id: str) -> None:
        """
        Remove `tenant_id`'s mapping from Postgres (the source of truth)
        and, best-effort, from the Redis cache (see CP-4). Postgres is
        deleted first and its failure propagates — an exception here
        must mean "the mapping might still exist", never "it's gone" when
        it isn't. The Redis-side cleanup follows the same advisory,
        never-load-bearing treatment as `get()`/`set()`'s `_redis_get`/
        `_redis_set` (see REL2-2): if it fails, the stale cache entry
        simply expires on its own TTL instead of aborting the deprovision.
        """
        await self.pg.delete(tenant_id)
        try:
            await self.redis.delete(tenant_id)
        except Exception:
            logger.exception(
                json.dumps(
                    {"event": "hybrid_tenant_store_redis_delete_failed", "tenant": tenant_id}
                )
            )

    async def list_tenant_ids(self, *, limit: int | None = None, offset: int = 0) -> list[str]:
        """
        Delegates to Postgres — the source of truth. Redis is a
        TTL-bounded cache of individual lookups and is not guaranteed to
        have ever seen every tenant, so it can't be used to enumerate
        them.

        `limit`/`offset` are forwarded as-is to
        `PostgresTenantStore.list_tenant_ids()` (see REL2-17).
        """
        return await self.pg.list_tenant_ids(limit=limit, offset=offset)

    async def _redis_get(self, tenant_id: str) -> str | None:
        try:
            return await self.redis.get(tenant_id)
        except Exception:
            logger.exception(
                json.dumps({"event": "hybrid_tenant_store_redis_get_failed", "tenant": tenant_id})
            )
            return None

    async def _redis_set(self, tenant_id: str, store_id: str) -> None:
        try:
            await self.redis.set(tenant_id, store_id, ex=300)
        except Exception:
            logger.exception(
                json.dumps({"event": "hybrid_tenant_store_redis_set_failed", "tenant": tenant_id})
            )

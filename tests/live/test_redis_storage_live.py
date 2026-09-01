"""
Regression coverage for REL-1/REL-2, against a real Redis instance.

`RedisTenantStore`/`RedisModelRegistry`'s own unit tests
(`tests/storage/test_redis_storage.py`) and `HybridTenantStore`'s
(`tests/storage/test_hybrid.py`) each use a bespoke fake shaped just for
that file — neither exercised the two real classes composed together
against a real `redis-py` client, which is exactly how the `set()`
signature mismatch (REL-1) and the undecoded-bytes bug (REL-2) shipped.
"""

import pytest

from py_authz.storage.hybrid import HybridTenantStore
from py_authz.storage.redis import RedisModelRegistry, RedisTenantStore

from .conftest import REDIS_URL, requires_redis


class InMemoryPg:
    """Stands in for `PostgresTenantStore` — Postgres isn't part of this
    live stack yet (see REL-3); Redis is the thing under test here."""

    def __init__(self):
        self._data: dict[str, str] = {}

    async def get(self, tenant_id: str) -> str | None:
        return self._data.get(tenant_id)

    async def set(self, tenant_id: str, store_id: str) -> None:
        self._data[tenant_id] = store_id


@requires_redis
@pytest.mark.asyncio
async def test_redis_tenant_store_round_trip_against_real_redis():
    store = RedisTenantStore(REDIS_URL)

    await store.set("t1", "store-1")
    result = await store.get("t1")

    assert result == "store-1"
    assert isinstance(result, str)  # not raw bytes — REL-2


@requires_redis
@pytest.mark.asyncio
async def test_redis_model_registry_round_trip_against_real_redis():
    registry = RedisModelRegistry(REDIS_URL)

    await registry.set("t1", "model-1")
    result = await registry.get("t1")

    assert result == "model-1"
    assert isinstance(result, str)


@requires_redis
@pytest.mark.asyncio
async def test_hybrid_store_composes_with_real_redis_tenant_store():
    """
    This is the exact composition REL-1 broke: `HybridTenantStore.set()`
    calls `redis_store.set(tenant_id, store_id, ex=300)` —
    `RedisTenantStore.set` previously had no `ex` parameter at all, so
    this raised `TypeError` against a real Redis the first time anything
    was written.
    """
    pg = InMemoryPg()
    redis_store = RedisTenantStore(REDIS_URL)
    store = HybridTenantStore(pg_store=pg, redis_store=redis_store)

    await store.set("t1", "store-1")

    assert await pg.get("t1") == "store-1"
    assert await redis_store.get("t1") == "store-1"

    # Served from the Redis cache without touching "Postgres" again.
    pg._data.clear()
    assert await store.get("t1") == "store-1"

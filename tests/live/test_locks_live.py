"""
Regression coverage for REL-6 (distributed-lock renewal), against a real
Redis instance.

`RedisLock`/`RedisLockManager` rely on Lua scripts (`EVAL`) for
compare-and-delete (`release`) and compare-and-extend (`renew`) — exactly
the kind of thing a hand-rolled fake can get subtly wrong (return-value
shape, `EXPIRE`'s actual semantics) without anyone noticing, since
`tests/core/test_locks.py`'s `FakeRedis` only mimics the behavior the unit
tests assert on.
"""

import pytest
import redis.asyncio as redis

from py_authz.core.locks import RedisLock, RedisLockManager

from .conftest import REDIS_URL, requires_redis


@pytest.fixture
async def redis_client():
    client = redis.from_url(REDIS_URL)
    try:
        yield client
    finally:
        await client.aclose()


@requires_redis
@pytest.mark.asyncio
async def test_acquire_release_round_trip_against_real_redis(redis_client):
    lock = RedisLock(redis_client)

    lock_id = await lock.acquire("py-authz-live-lock:1", ttl=5)
    assert await redis_client.get("py-authz-live-lock:1") == lock_id.encode()

    await lock.release("py-authz-live-lock:1", lock_id)
    assert await redis_client.get("py-authz-live-lock:1") is None


@requires_redis
@pytest.mark.asyncio
async def test_release_is_a_noop_for_a_non_owned_key(redis_client):
    lock = RedisLock(redis_client)

    await redis_client.set("py-authz-live-lock:2", "someone-else", ex=5)

    await lock.release("py-authz-live-lock:2", "not-the-owner")

    # Untouched — release must not delete a lock it doesn't own.
    assert await redis_client.get("py-authz-live-lock:2") == b"someone-else"
    await redis_client.delete("py-authz-live-lock:2")


@requires_redis
@pytest.mark.asyncio
async def test_renew_extends_ttl_against_real_redis(redis_client):
    lock = RedisLock(redis_client)
    key = "py-authz-live-lock:3"

    lock_id = await lock.acquire(key, ttl=2)
    initial_ttl = await redis_client.ttl(key)
    assert 0 < initial_ttl <= 2

    renewed = await lock.renew(key, lock_id, ttl=60)
    assert renewed is True

    extended_ttl = await redis_client.ttl(key)
    assert extended_ttl > initial_ttl

    await lock.release(key, lock_id)


@requires_redis
@pytest.mark.asyncio
async def test_renew_fails_for_a_non_owned_key(redis_client):
    lock = RedisLock(redis_client)
    key = "py-authz-live-lock:4"

    await redis_client.set(key, "someone-else", ex=2)

    assert await lock.renew(key, "not-the-owner", ttl=60) is False
    # TTL must be unchanged — no expire call should have gone through.
    assert await redis_client.ttl(key) <= 2

    await redis_client.delete(key)


@requires_redis
@pytest.mark.asyncio
async def test_manager_lock_keeps_key_alive_past_initial_ttl_via_renewal(redis_client):
    """
    The actual scenario REL-6 fixes: a critical section that outlives the
    lock's initial TTL must not have Redis expire the key out from under
    it — background renewal must keep it alive against a real server.
    """
    import asyncio

    mgr = RedisLockManager(redis_client)
    key = "py-authz-live-lock:5"

    async with mgr.lock(key, ttl=1, renew_interval=0.3):
        # Sleep past the *initial* TTL — without renewal, Redis would
        # have expired and removed the key by now.
        await asyncio.sleep(1.5)
        assert await redis_client.exists(key) == 1

    # Released cleanly on exit.
    assert await redis_client.exists(key) == 0

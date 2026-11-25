import asyncio

import pytest

from py_authz.core.exceptions import LockAcquisitionTimeout
from py_authz.core.locks import RedisLock, RedisLockManager


def _count_renewals(monkeypatch, *, at_least: int) -> asyncio.Event:
    """Patch `RedisLock.renew` to set the returned event once it has been
    called `at_least` times (DX3-5: event-driven, no fixed sleeps)."""
    event = asyncio.Event()
    calls = 0
    real_renew = RedisLock.renew

    async def counting_renew(self, key, lock_id, ttl):
        nonlocal calls
        result = await real_renew(self, key, lock_id, ttl)
        calls += 1
        if calls >= at_least:
            event.set()
        return result

    monkeypatch.setattr(RedisLock, "renew", counting_renew)
    return event


class FakeRedis:
    """Minimal async Redis stand-in for distributed lock semantics."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self._ttls: dict[str, int] = {}
        self.set_calls: list[dict] = []
        self.eval_calls: list[tuple] = []

    async def set(self, key, value, nx=False, ex=None):
        self.set_calls.append({"key": key, "value": value, "nx": nx, "ex": ex})
        if nx and key in self._store:
            return None
        self._store[key] = value
        self._ttls[key] = ex
        return True

    async def eval(self, script, numkeys, *args):
        self.eval_calls.append((script, numkeys, args))
        key = args[0]
        lock_id = args[1]

        if self._store.get(key) != lock_id:
            return 0

        if '"del"' in script:
            del self._store[key]
            self._ttls.pop(key, None)
            return 1

        if '"expire"' in script:
            self._ttls[key] = args[2]
            return 1

        raise AssertionError(f"FakeRedis.eval: unrecognized script:\n{script}")


@pytest.mark.asyncio
async def test_acquire_sets_key_with_nx_and_ttl():
    r = FakeRedis()
    lock = RedisLock(r)

    lock_id = await lock.acquire("k1", ttl=42)

    assert isinstance(lock_id, str) and lock_id
    assert r.set_calls[0] == {"key": "k1", "value": lock_id, "nx": True, "ex": 42}


@pytest.mark.asyncio
async def test_acquire_times_out_when_key_held():
    r = FakeRedis()
    r._store["busy"] = "someone-else"
    lock = RedisLock(r)

    with pytest.raises(LockAcquisitionTimeout):
        await lock.acquire("busy", retry_interval=0.01, timeout=0.05)


@pytest.mark.asyncio
async def test_release_only_deletes_when_owner_matches():
    r = FakeRedis()
    lock = RedisLock(r)

    lock_id = await lock.acquire("k2")
    await lock.release("k2", "not-the-owner")
    assert "k2" in r._store  # still held

    await lock.release("k2", lock_id)
    assert "k2" not in r._store


@pytest.mark.asyncio
async def test_manager_lock_context_releases_on_exit():
    """
    Regression test: `lock` method used to be shadowed by a `self.lock`
    instance attribute, making `manager.lock(...)` uncallable.
    """
    r = FakeRedis()
    mgr = RedisLockManager(r)

    async with mgr.lock("k3", ttl=10):
        assert "k3" in r._store

    assert "k3" not in r._store


@pytest.mark.asyncio
async def test_manager_releases_even_when_body_raises():
    r = FakeRedis()
    mgr = RedisLockManager(r)

    with pytest.raises(RuntimeError):
        async with mgr.lock("k4"):
            raise RuntimeError("boom")

    assert "k4" not in r._store


@pytest.mark.asyncio
async def test_renew_extends_ttl_only_when_owner_matches():
    r = FakeRedis()
    lock = RedisLock(r)

    lock_id = await lock.acquire("k5", ttl=1)

    assert await lock.renew("k5", "not-the-owner", ttl=99) is False
    assert r._ttls["k5"] == 1  # unchanged

    assert await lock.renew("k5", lock_id, ttl=99) is True
    assert r._ttls["k5"] == 99


@pytest.mark.asyncio
async def test_manager_lock_renews_ttl_while_body_is_running(monkeypatch):
    """
    Regression test for REL-6: a critical section that outlives the
    initial TTL must not have its lock silently expire out from under it
    — a background renewal keeps re-extending it for as long as the
    `async with` body is running.
    """
    r = FakeRedis()
    mgr = RedisLockManager(r)
    renewed = _count_renewals(monkeypatch, at_least=2)

    async with mgr.lock("k6", ttl=1, renew_interval=0.01):
        # DX3-5: wait for the renewals themselves, not a fixed sleep.
        await asyncio.wait_for(renewed.wait(), timeout=5)

    renewal_calls = [c for c in r.eval_calls if '"expire"' in c[0]]
    assert len(renewal_calls) >= 2
    assert "k6" not in r._store  # still released cleanly on exit


@pytest.mark.asyncio
async def test_manager_lock_renewal_survives_transient_renew_errors():
    """
    Regression test for REL2-7: a *transient* error renewing (e.g. Redis
    unreachable for one call) must not be treated the same as "the lock
    is legitimately gone" — the renewal loop must log it and keep trying
    on subsequent intervals, not silently stop.
    """
    r = FakeRedis()
    mgr = RedisLockManager(r)

    call_count = 0
    real_renew = RedisLock.renew

    succeeded = asyncio.Event()

    async def flaky_renew(self, key, lock_id, ttl):
        nonlocal call_count
        call_count += 1
        if call_count <= 2:
            raise ConnectionError("redis unavailable")
        result = await real_renew(self, key, lock_id, ttl)
        succeeded.set()
        return result

    RedisLock.renew = flaky_renew
    try:
        body_completed = False
        async with mgr.lock("k8", ttl=1, renew_interval=0.01):
            await asyncio.wait_for(succeeded.wait(), timeout=5)
            body_completed = True
    finally:
        RedisLock.renew = real_renew

    assert body_completed is True
    assert call_count >= 3  # retried past the transient failures
    renewal_calls = [c for c in r.eval_calls if '"expire"' in c[0]]
    assert len(renewal_calls) >= 1  # eventually succeeded at least once
    assert "k8" not in r._store  # still released cleanly on exit


@pytest.mark.asyncio
async def test_manager_lock_renewal_survives_lost_lock_without_crashing(monkeypatch):
    """
    If renewal discovers the lock is no longer held (e.g. it expired for
    real and someone else acquired it), the renewal loop must stop
    quietly rather than raising into the running critical section — the
    lock is advisory, not a hard cancellation mechanism.
    """
    r = FakeRedis()
    mgr = RedisLockManager(r)

    body_completed = False
    renewed = _count_renewals(monkeypatch, at_least=1)

    async with mgr.lock("k7", ttl=1, renew_interval=0.01):
        # Simulate another process having taken over the key.
        r._store["k7"] = "someone-else"
        await asyncio.wait_for(renewed.wait(), timeout=5)
        body_completed = True

    assert body_completed is True

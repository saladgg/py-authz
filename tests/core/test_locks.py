import pytest

from py_authz.core.locks import RedisLock, RedisLockManager


class FakeRedis:
    """Minimal async Redis stand-in for distributed lock semantics."""

    def __init__(self):
        self._store: dict[str, str] = {}
        self.set_calls: list[dict] = []
        self.eval_calls: list[tuple] = []

    async def set(self, key, value, nx=False, ex=None):
        self.set_calls.append({"key": key, "value": value, "nx": nx, "ex": ex})
        if nx and key in self._store:
            return None
        self._store[key] = value
        return True

    async def eval(self, script, numkeys, *args):
        self.eval_calls.append((script, numkeys, args))
        key = args[0]
        lock_id = args[1]
        if self._store.get(key) == lock_id:
            del self._store[key]
            return 1
        return 0


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

    with pytest.raises(TimeoutError):
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

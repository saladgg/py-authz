import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

from py_authz.core.logging import logger
from py_authz.utils.deps import require_redis

if TYPE_CHECKING:
    from redis.asyncio import Redis
else:
    require_redis()


class RedisLock:
    """
    Distributed lock using Redis.

    Uses:
        SET key value NX EX ttl
    """

    def __init__(self, client: "Redis"):
        self.client = client

    async def acquire(
        self,
        key: str,
        ttl: int = 30,
        retry_interval: float = 0.1,
        timeout: float = 5,
    ) -> str:
        """
        Acquire a lock.

        Returns:
            lock_id (str)

        Raises:
            TimeoutError if lock not acquired
        """
        lock_id = str(uuid.uuid4())
        elapsed = 0.0

        while elapsed < timeout:
            acquired = await self.client.set(
                key,
                lock_id,
                nx=True,
                ex=ttl,
            )

            if acquired:
                return lock_id

            await asyncio.sleep(retry_interval)
            elapsed += retry_interval

        raise TimeoutError(f"Failed to acquire lock: {key}")

    async def release(self, key: str, lock_id: str):
        """
        Release lock safely (only if owned).
        """
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("del", KEYS[1])
        else
            return 0
        end
        """

        await self.client.eval(script, 1, key, lock_id)  # type: ignore[misc]

    async def renew(self, key: str, lock_id: str, ttl: int) -> bool:
        """
        Extend the lock's TTL, but only if we still hold it
        (compare-and-extend, mirroring `release`'s compare-and-delete).

        Returns:
            bool: whether the renewal succeeded. `False` means we no
            longer hold the lock (e.g. it already expired and someone
            else acquired it) — the caller should treat this as having
            lost the lock.
        """
        script = """
        if redis.call("get", KEYS[1]) == ARGV[1] then
            return redis.call("expire", KEYS[1], ARGV[2])
        else
            return 0
        end
        """

        result = await self.client.eval(script, 1, key, lock_id, ttl)  # type: ignore[misc]
        return bool(result)


class RedisLockManager:
    def __init__(self, client: "Redis"):
        self._lock = RedisLock(client)

    @asynccontextmanager
    async def lock(self, key: str, ttl: int = 30, *, renew_interval: float | None = None):
        """
        Args:
            key: lock key.

            ttl: initial (and renewed) lock TTL in seconds.

            renew_interval: how often (seconds) to renew the lock's TTL
                while the `async with` body is running. Defaults to
                `ttl / 3` — a conventional safety margin that renews well
                before the lock would expire. This is what lets a
                critical section that takes longer than `ttl` (e.g.
                tenant provisioning under load) keep its lock instead of
                it silently expiring mid-operation and letting a second
                caller acquire the "released" lock — see REL-6.

                Renewal failure (we no longer hold the lock — e.g. Redis
                was unreachable for longer than `ttl` and someone else
                acquired it) is logged as a warning but does not abort
                the running body: this lock is advisory, not a hard
                cancellation mechanism, so a caller relying on renewal
                for correctness should still make its own critical
                section idempotent (as `TenantManager.provision()` does,
                via its own re-check-under-lock).
        """
        lock_id = await self._lock.acquire(key, ttl=ttl)
        interval = renew_interval if renew_interval is not None else max(ttl / 3, 0.01)

        stop_event = asyncio.Event()

        async def _renew_loop() -> None:
            while True:
                try:
                    await asyncio.wait_for(stop_event.wait(), timeout=interval)
                    return  # stop_event was set — body finished, nothing more to do
                except TimeoutError:
                    renewed = await self._lock.renew(key, lock_id, ttl)
                    if not renewed:
                        logger.warning(
                            f"lock_renewal_failed key={key} — lock no longer held; "
                            "the running critical section is continuing regardless"
                        )
                        return

        renew_task = asyncio.ensure_future(_renew_loop())

        try:
            yield
        finally:
            stop_event.set()
            try:
                await renew_task
            except Exception:  # pragma: no cover — defensive; _renew_loop doesn't raise
                logger.exception(f"lock_renewal_task_failed key={key}")
            await self._lock.release(key, lock_id)

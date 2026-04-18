import asyncio
import uuid
from contextlib import asynccontextmanager
from typing import TYPE_CHECKING

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


class RedisLockManager:
    def __init__(self, client: "Redis"):
        self._lock = RedisLock(client)

    @asynccontextmanager
    async def lock(self, key: str, ttl: int = 30):
        lock_id = await self._lock.acquire(key, ttl=ttl)

        try:
            yield
        finally:
            await self._lock.release(key, lock_id)

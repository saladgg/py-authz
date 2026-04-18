from py_authz.cache.base import BaseCache
from py_authz.utils.deps import require_redis

redis = require_redis()


class RedisCache(BaseCache):
    """
    Redis-based cache implementation.

    Suitable for:
        - Production environments
        - Distributed systems
        - Multi-instance deployments

    Features:
        - TTL support via Redis expiration
        - Async operations
        - Shared cache across services

    Notes:
        - Requires a running Redis instance
        - Network latency applies (unlike in-memory cache)
    """

    def __init__(
        self,
        url: str = "redis://localhost:6379/0",
        *,
        prefix: str = "py_authz:",
    ):
        """
        Initialize Redis cache.

        Args:
            url (str):
                Redis connection URL.

            prefix (str):
                Prefix for all cache keys (namespacing).
        """
        self._client = redis.from_url(url)
        self._prefix = prefix

    def _key(self, key: str) -> str:
        """
        Apply namespace prefix to cache key.
        """
        return f"{self._prefix}{key}"

    async def get(self, key: str) -> bool | None:
        """
        Retrieve a value from Redis.

        Args:
            key (str): Cache key

        Returns:
            Optional[bool]:
                True/False if present, None if missing
        """
        value = await self._client.get(self._key(key))

        if value is None:
            return None

        # Redis stores bytes → decode
        return value.decode() == "1"

    async def set(self, key: str, value: bool, ttl: int = 60) -> None:
        """
        Store a value in Redis with TTL.

        Args:
            key (str): Cache key
            value (bool): Value to store
            ttl (int): Time-to-live in seconds
        """
        encoded = "1" if value else "0"

        await self._client.set(
            self._key(key),
            encoded,
            ex=ttl,
        )

    async def delete(self, key: str) -> None:
        """
        Delete a key from Redis.
        """
        await self._client.delete(self._key(key))

    async def clear(self) -> None:
        """
        Clear all keys with this prefix.

        WARNING:
            This scans and deletes keys—can be expensive in large datasets.
        """
        pattern = f"{self._prefix}*"

        async for key in self._client.scan_iter(match=pattern):
            await self._client.delete(key)

    async def close(self) -> None:
        """
        Close Redis connection.

        Should be called on application shutdown.
        """
        await self._client.aclose()

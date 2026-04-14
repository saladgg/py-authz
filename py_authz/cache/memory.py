import time
import asyncio
from typing import Optional, Dict, Tuple

from .base import BaseCache


class InMemoryCache(BaseCache):
    """
    Simple in-memory cache implementation.

    This cache is suitable for:
        - Development environments
        - Small-scale applications
        - Testing

    It is NOT suitable for:
        - Multi-process deployments
        - Distributed systems

    Features:
        - TTL-based expiration
        - Async-compatible interface
        - Lightweight and dependency-free

    Notes:
        - This implementation is not fully thread-safe.
        - For production, consider using Redis or another external cache.
    """

    def __init__(self):
        """
        Initialize the in-memory cache.
        """
        # Store format:
        # key -> (value, expiry_timestamp)
        self._store: Dict[str, Tuple[bool, float]] = {}

        # Optional lock for safer concurrent access
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[bool]:
        """
        Retrieve a value from the cache.

        Args:
            key (str): Cache key.

        Returns:
            Optional[bool]:
                Cached value if present and not expired, otherwise None.
        """
        async with self._lock:
            item = self._store.get(key)

            if item is None:
                return None

            value, expiry = item

            # Check TTL expiration
            if expiry < time.time():
                # Remove expired entry
                del self._store[key]
                return None

            return value

    async def set(self, key: str, value: bool, ttl: int = 60) -> None:
        """
        Store a value in the cache with TTL.

        Args:
            key (str): Cache key.
            value (bool): Value to store.
            ttl (int): Time-to-live in seconds.
        """
        expiry = time.time() + ttl

        async with self._lock:
            self._store[key] = (value, expiry)

    async def delete(self, key: str) -> None:
        """
        Delete a key from the cache.

        Args:
            key (str): Cache key.
        """
        async with self._lock:
            self._store.pop(key, None)

    async def clear(self) -> None:
        """
        Clear all cache entries.
        """
        async with self._lock:
            self._store.clear()
import asyncio
import time
from collections import OrderedDict
from collections.abc import Callable

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

    def __init__(
        self,
        *,
        max_size: int | None = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ):
        """
        Args:
            max_size: maximum number of entries kept at once —
                least-recently-used evicted first once exceeded. A key
                written once and never read again used to stay forever
                (expired entries were only ever purged lazily, on a
                subsequent `get()` for that *same* key), a plain memory
                leak under sustained load in a process using this cache
                as shipped (see REL2-5). `None` restores the old,
                unbounded behavior.
            clock: seconds source used for TTLs (DX3-5). Defaults to
                `time.monotonic`, so a wall-clock jump (NTP, DST) can't
                expire or resurrect entries; it was `time.time()`. Tests
                inject a fake clock instead of sleeping.
        """
        self._clock = clock
        # Store format:
        # key -> (value, expiry_timestamp)
        # An OrderedDict so both TTL expiry and LRU eviction can share one
        # structure: `move_to_end()` on every access/write keeps the
        # least-recently-used entry at the front, cheap to evict from.
        self._store: OrderedDict[str, tuple[bool, float]] = OrderedDict()
        self.max_size = max_size

        # Optional lock for safer concurrent access
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> bool | None:
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
            if expiry <= self._clock():
                # Remove expired entry
                del self._store[key]
                return None

            self._store.move_to_end(key)
            return value

    async def set(self, key: str, value: bool, ttl: int = 60) -> None:
        """
        Store a value in the cache with TTL.

        Args:
            key (str): Cache key.
            value (bool): Value to store.
            ttl (int): Time-to-live in seconds.
        """
        expiry = self._clock() + ttl

        async with self._lock:
            self._store[key] = (value, expiry)
            self._store.move_to_end(key)

            if self.max_size is not None:
                while len(self._store) > self.max_size:
                    self._store.popitem(last=False)

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

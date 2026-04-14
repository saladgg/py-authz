from abc import ABC, abstractmethod
from typing import Optional


class BaseCache(ABC):
    """
    Abstract base class for cache backends.

    This defines the contract that all cache implementations must follow.
    It enables pluggable caching strategies (e.g., in-memory, Redis).

    Design Principles:
        - Async-first (to support modern Python frameworks)
        - Minimal interface (get/set/delete)
        - TTL support for cache invalidation
    """

    @abstractmethod
    async def get(self, key: str) -> Optional[bool]:
        """
        Retrieve a value from the cache.

        Args:
            key (str):
                Cache key.

        Returns:
            Optional[bool]:
                - True/False if present
                - None if key is not found or expired

        Notes:
            - Must NOT raise an exception on cache miss.
            - Should be safe for concurrent access.
        """
        raise NotImplementedError

    @abstractmethod
    async def set(self, key: str, value: bool, ttl: int = 60) -> None:
        """
        Store a value in the cache.

        Args:
            key (str):
                Cache key.

            value (bool):
                Authorization result to cache.

            ttl (int):
                Time-to-live in seconds.

        Notes:
            - Implementations should handle TTL expiration internally.
            - Overwriting existing keys is allowed.
        """
        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: str) -> None:
        """
        Remove a key from the cache.

        Args:
            key (str):
                Cache key to delete.

        Notes:
            - Should NOT raise an error if the key does not exist.
        """
        raise NotImplementedError

    @abstractmethod
    async def clear(self) -> None:
        """
        Clear all cache entries.

        Notes:
            - Primarily used for testing or administrative purposes.
            - Use with caution in production environments.
        """
        raise NotImplementedError
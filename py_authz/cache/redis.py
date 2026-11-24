from py_authz.cache.base import BaseCache
from py_authz.utils.deps import REDIS_CLIENT_DEFAULTS, require_redis

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
        client=None,
    ):
        """
        Initialize Redis cache.

        Args:
            url (str):
                Redis connection URL. Ignored if `client` is given.

            prefix (str):
                Prefix for all cache keys (namespacing).

            client:
                An existing `redis.asyncio.Redis`-shaped client to use
                instead of constructing one from `url` — lets a host app
                that already owns a Redis connection pool hand it over
                instead of this class always opening its own (see
                ARCH2-18). Previously the only way to do this was to
                monkeypatch the private `_client` attribute after
                construction.
        """
        self._client = (
            client if client is not None else redis.from_url(url, **REDIS_CLIENT_DEFAULTS)
        )
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
        await self._delete_matching(f"{_glob_escape(self._prefix)}*")

    async def close(self) -> None:
        """
        Close Redis connection.

        Should be called on application shutdown.
        """
        await self._client.aclose()

    # ------------------------------------------------------------------
    # Introspection / bulk invalidation (CP-9)
    # ------------------------------------------------------------------
    #
    # `BaseCache`'s own interface is deliberately single-key (`get`/`set`/
    # `delete`) or clear-everything (`clear`) — there was no "how many
    # keys are cached" or "invalidate every key matching this fragment"
    # short of a full `clear()`. Both are Redis-specific (an in-memory
    # cache has no cross-process introspection story worth building), and
    # both reuse `clear()`'s existing `SCAN`-based approach rather than
    # `DBSIZE` (counts the whole keyspace, not just this cache's prefix)
    # or `KEYS` (blocks the server on a large keyspace).

    async def count_keys(self, *, fragment: str = "") -> int:
        """
        Count keys under this cache's prefix, optionally narrowed to
        those also containing `fragment` (e.g. a tenant's `cache_namespace`
        or an `AuthzRequest.identity_prefix(...)` result).
        """
        prefix = _glob_escape(self._prefix)
        pattern = f"{prefix}*{_glob_escape(fragment)}*" if fragment else f"{prefix}*"
        count = 0
        async for _ in self._client.scan_iter(match=pattern, count=_SCAN_COUNT):
            count += 1
        return count

    async def delete_by_fragment(self, fragment: str) -> int:
        """
        Bulk-delete every key under this cache's prefix that also
        contains `fragment` — the "invalidate all cached decisions for
        this user/tenant" pattern `docs/architecture.md`'s Caching
        section already documents as the recommended approach, shipped
        here as reusable library code instead of every adopter
        hand-rolling the same `SCAN` loop.

        `fragment` is matched anywhere in the key, not just as a prefix,
        since `AuthzEngine`'s `cache_namespace` (a tenant's `store_id`)
        comes *before* `AuthzRequest.cache_key()`'s own fields in the
        stored key (`f"{cache_namespace}:{key}"`), while
        `AuthzRequest.identity_prefix(...)` describes a fragment that
        starts partway through the same key for a namespaced cache — a
        pure prefix match can't express "this tenant AND this user"
        without the caller pre-concatenating both. Pass a non-empty,
        sufficiently specific `fragment` — an empty one would match (and
        delete) every key this cache owns, same as `clear()`.

        Returns:
            int: number of keys deleted.
        """
        if not fragment:
            raise ValueError("fragment must be non-empty — use clear() to delete everything")

        # Escaped (SEC3-6): `fragment` comes from an API caller, and an
        # unescaped `*`/`?`/`[` would widen the match — `"*"` used to wipe
        # the entire cache.
        return await self._delete_matching(
            f"{_glob_escape(self._prefix)}*{_glob_escape(fragment)}*"
        )

    async def delete_by_prefix(self, key_prefix: str) -> int:
        """
        Bulk-delete every key whose (unprefixed) cache key *starts with*
        `key_prefix` — e.g. `f"{store_id}:"` for every decision cached by
        one tenant's engine (`AuthzEngine(cache_namespace=store_id)`), or
        `f"{store_id}:{AuthzRequest.identity_prefix(user)}"` for one user
        within one tenant. Prefer this over `delete_by_fragment()`
        whenever the scope is known: a prefix can't accidentally match a
        key where the same text happens to appear later on (SEC3-6).

        Returns:
            int: number of keys deleted.
        """
        if not key_prefix:
            raise ValueError("key_prefix must be non-empty — use clear() to delete everything")
        return await self._delete_matching(f"{_glob_escape(self._prefix + key_prefix)}*")

    async def _delete_matching(self, pattern: str) -> int:
        """`SCAN` with a large `COUNT` and `UNLINK` in batches (REL3-18) —
        previously one `DELETE` round trip per key on a `COUNT 10` scan,
        i.e. ~100k SCANs and up to 1M round trips for 1M keys."""
        deleted = 0
        batch: list = []
        async for key in self._client.scan_iter(match=pattern, count=_SCAN_COUNT):
            batch.append(key)
            if len(batch) >= _DELETE_BATCH:
                deleted += await self._client.unlink(*batch)
                batch.clear()
        if batch:
            deleted += await self._client.unlink(*batch)
        return deleted


_SCAN_COUNT = 1000
_DELETE_BATCH = 500


def _glob_escape(value: str) -> str:
    """Escape Redis `MATCH` glob metacharacters so `value` matches only
    itself."""
    out = []
    for ch in value:
        if ch in "\\*?[]":
            out.append("\\")
        out.append(ch)
    return "".join(out)

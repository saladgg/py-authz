from py_authz.core.exceptions import ConfigurationError
from py_authz.utils.deps import require_redis

redis = require_redis()


def _build_client(url: str | None, client):
    """Shared `url`-or-`client` resolution for `RedisTenantStore`/
    `RedisModelRegistry` (see ARCH2-18)."""
    if client is not None:
        return client
    if url is not None:
        return redis.from_url(url)
    raise ConfigurationError("Either `url` or `client` must be provided")


class RedisTenantStore:
    def __init__(self, url: str | None = None, *, client=None):
        """
        Args:
            url: Redis connection URL. Ignored if `client` is given.
            client: an existing `redis.asyncio.Redis`-shaped client to use
                instead of constructing one from `url` — lets a host app
                that already owns a Redis connection pool hand it over
                instead of this class always opening its own (see
                ARCH2-18).
        """
        self.client = _build_client(url, client)

    async def get(self, tenant_id: str) -> str | None:
        value = await self.client.get(f"tenant:{tenant_id}:store")

        if value is None:
            return None

        # redis-py returns bytes by default — decode so callers (e.g.
        # `MultiTenantAuthz.for_tenant`, `OpenFGAClient(store_id=...)`)
        # get the `str` they expect.
        return value.decode() if isinstance(value, bytes) else value

    async def set(self, tenant_id: str, store_id: str, ex: int | None = None) -> None:
        """
        Args:
            ex (Optional[int]):
                Expiry in seconds. `None` (the default) means the mapping
                never expires — the usual case for a tenant→store mapping.
                Accepting it at all is what lets this class compose with
                `HybridTenantStore`, which caches with a TTL.
        """
        await self.client.set(f"tenant:{tenant_id}:store", store_id, ex=ex)

    async def list_tenant_ids(self) -> list[str]:
        """
        Enumerate every tenant this store knows about via `SCAN` (not
        `KEYS` — `SCAN` doesn't block the server on a large keyspace).
        Note: if this store is used behind a `HybridTenantStore`, a
        tenant's mapping only lives here once it's been read/written at
        least once with a TTL still unexpired — prefer
        `HybridTenantStore.list_tenant_ids()` (delegating to Postgres,
        the source of truth) when composing the two.
        """
        prefix = "tenant:"
        suffix = ":store"
        tenant_ids = []

        async for key in self.client.scan_iter(match=f"{prefix}*{suffix}"):
            key_str = key.decode() if isinstance(key, bytes) else key
            tenant_ids.append(key_str[len(prefix) : -len(suffix)])

        return tenant_ids

    async def close(self) -> None:
        """
        Close the underlying Redis connection.

        Added for symmetry with `PostgresTenantStore`/`RedisModelRegistry`
        — lets callers (e.g. the CLI's `migrate` command, see REL2-8)
        release the connection via `hasattr(store, "close")` duck-typing
        without special-casing this class.
        """
        await self.client.aclose()


class RedisModelRegistry:
    def __init__(self, url: str | None = None, *, client=None):
        """See `RedisTenantStore.__init__` — same `client=` injection
        option (ARCH2-18)."""
        self.client = _build_client(url, client)

    async def get(self, tenant_id: str) -> str | None:
        value = await self.client.get(f"tenant:{tenant_id}:model")

        if value is None:
            return None

        return value.decode() if isinstance(value, bytes) else value

    async def set(self, tenant_id: str, model_id: str, ex: int | None = None) -> None:
        await self.client.set(f"tenant:{tenant_id}:model", model_id, ex=ex)

    async def close(self) -> None:
        """See `RedisTenantStore.close()` (REL2-8)."""
        await self.client.aclose()

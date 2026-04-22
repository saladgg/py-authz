"""
03 — Caching authorization decisions.

Every `AuthzEngine.enforce()` call hits OpenFGA. That's fine at low RPS, but
hot paths (request-per-page auth checks) benefit from memoizing the boolean
result for a few seconds. `BaseCache` is the pluggable interface:

    - `InMemoryCache`  — process-local, zero deps. Good for tests / single-box.
    - `RedisCache`     — shared across processes. Requires py-authz[redis].

The engine uses the cache transparently: `get` before the OpenFGA call, `set`
after. Cache key is `{user_id}:{action}:{resource_type}:{resource_id}`.
"""

from __future__ import annotations

import asyncio
import os
import time

from py_authz import Authz, Identity, Resource
from py_authz.cache.memory import InMemoryCache
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


async def main() -> None:
    cache = InMemoryCache()

    # Uncomment to use Redis instead (requires `pip install py-authz[redis]`):
    # from py_authz.cache.redis import RedisCache
    # cache = RedisCache(url=os.environ.get("REDIS_URL", "redis://localhost:6379/0"))

    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    engine = AuthzEngine(fga_client=client, cache=cache)
    authz = Authz(engine)

    alice = Identity(id="user:alice")
    roadmap = Resource(type="document", id="roadmap")

    try:
        # First call: goes to OpenFGA
        t0 = time.perf_counter()
        await authz.enforce("viewer", alice, roadmap)
        cold_ms = (time.perf_counter() - t0) * 1000

        # Subsequent calls: served from cache
        t0 = time.perf_counter()
        for _ in range(100):
            await authz.enforce("viewer", alice, roadmap)
        warm_ms = (time.perf_counter() - t0) * 1000 / 100

        print(f"cold lookup:  {cold_ms:7.2f} ms")
        print(f"cached avg:   {warm_ms:7.2f} ms")

        # Manually invalidate a cache entry, e.g. after a permission change.
        await cache.delete("user:alice:viewer:document:roadmap")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

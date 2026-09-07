import pytest

from py_authz.core.exceptions import ConfigurationError
from py_authz.storage import redis as redis_store_module
from py_authz.storage.redis import RedisModelRegistry, RedisTenantStore


class FakeAsyncRedis:
    """
    Mimics real `redis-py` behavior closely enough to catch the class of
    bug REL-1/REL-2 shipped as: values are stored and returned as `bytes`
    (never the plain `str` a less faithful double might use), and `set()`
    accepts the same `ex` keyword real `redis-py` does.
    """

    def __init__(self):
        self.store: dict[str, bytes] = {}
        self.urls: list[str] = []
        self.set_calls: list[tuple[str, str, int | None]] = []

    async def get(self, key):
        return self.store.get(key)

    async def set(self, key, value, ex=None):
        self.store[key] = value.encode() if isinstance(value, str) else value
        self.set_calls.append((key, value, ex))

    async def delete(self, key):
        self.store.pop(key, None)

    async def scan_iter(self, match=None):
        import fnmatch

        for key in list(self.store):
            if match is None or fnmatch.fnmatch(key, match):
                yield key.encode()  # real redis-py yields bytes by default


class FakeRedisModule:
    def __init__(self):
        self.clients: list[FakeAsyncRedis] = []

    def from_url(self, url):
        client = FakeAsyncRedis()
        client.urls.append(url)
        self.clients.append(client)
        return client


@pytest.fixture
def patched_redis(monkeypatch):
    fake = FakeRedisModule()
    monkeypatch.setattr(redis_store_module, "redis", fake)
    return fake


@pytest.mark.asyncio
async def test_tenant_store_set_and_get(patched_redis):
    store = RedisTenantStore("redis://fake")

    await store.set("t1", "store-1")

    # Regression test for REL-2: the real client returns bytes — this
    # must come back as `str`, not the raw bytes object.
    result = await store.get("t1")
    assert result == "store-1"
    assert isinstance(result, str)
    # key namespace is preserved
    assert "tenant:t1:store" in store.client.store


@pytest.mark.asyncio
async def test_tenant_store_get_returns_none_when_missing(patched_redis):
    store = RedisTenantStore("redis://fake")

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_tenant_store_set_accepts_ex_kwarg(patched_redis):
    """
    Regression test for REL-1: `HybridTenantStore.set()` calls
    `self.redis.set(tenant_id, store_id, ex=300)` — `RedisTenantStore.set`
    must accept (and forward) that keyword, not raise `TypeError`.
    """
    store = RedisTenantStore("redis://fake")

    await store.set("t1", "store-1", ex=300)

    assert store.client.set_calls == [("tenant:t1:store", "store-1", 300)]


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids(patched_redis):
    """
    Regression test for DX-5: enumerating tenants via `SCAN` over
    `tenant:*:store` keys, stripping the prefix/suffix back to the bare
    tenant id.
    """
    store = RedisTenantStore("redis://fake")

    await store.set("t1", "store-1")
    await store.set("t2", "store-2")

    assert set(await store.list_tenant_ids()) == {"t1", "t2"}


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids_empty_when_no_tenants(patched_redis):
    store = RedisTenantStore("redis://fake")

    assert await store.list_tenant_ids() == []


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids_respects_limit(patched_redis):
    """REL2-17: `limit` bounds how many ids are collected before the SCAN
    loop stops, rather than always enumerating the entire keyspace."""
    store = RedisTenantStore("redis://fake")

    await store.set("t1", "store-1")
    await store.set("t2", "store-2")
    await store.set("t3", "store-3")

    result = await store.list_tenant_ids(limit=2)

    assert len(result) == 2
    assert set(result).issubset({"t1", "t2", "t3"})


@pytest.mark.asyncio
async def test_model_registry_round_trip(patched_redis):
    reg = RedisModelRegistry("redis://fake")

    await reg.set("t1", "model-1")

    result = await reg.get("t1")
    assert result == "model-1"
    assert isinstance(result, str)
    assert "tenant:t1:model" in reg.client.store


@pytest.mark.asyncio
async def test_model_registry_set_accepts_ex_kwarg(patched_redis):
    reg = RedisModelRegistry("redis://fake")

    await reg.set("t1", "model-1", ex=300)

    assert reg.client.set_calls == [("tenant:t1:model", "model-1", 300)]


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-18: `client=` lets a host app that
# already owns a Redis client hand it to these classes directly, instead
# of `redis.from_url(url)` always being called internally.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_store_accepts_injected_client(patched_redis):
    from tests.storage.test_redis_storage import FakeAsyncRedis

    injected = FakeAsyncRedis()
    store = RedisTenantStore(client=injected)

    await store.set("t1", "store-1")

    assert store.client is injected
    assert patched_redis.clients == []  # from_url() never called


@pytest.mark.asyncio
async def test_model_registry_accepts_injected_client(patched_redis):
    from tests.storage.test_redis_storage import FakeAsyncRedis

    injected = FakeAsyncRedis()
    reg = RedisModelRegistry(client=injected)

    await reg.set("t1", "model-1")

    assert reg.client is injected
    assert patched_redis.clients == []


def test_tenant_store_requires_url_or_client():
    with pytest.raises(ConfigurationError):
        RedisTenantStore()


def test_model_registry_requires_url_or_client():
    with pytest.raises(ConfigurationError):
        RedisModelRegistry()


@pytest.mark.asyncio
async def test_tenant_store_close_closes_underlying_client(patched_redis):
    """Regression test for REL2-8: `close()` didn't exist on this class
    at all, so the CLI's `migrate` command had no way to release it."""

    class ClosableFakeRedis(FakeAsyncRedis):
        def __init__(self):
            super().__init__()
            self.closed = False

        async def aclose(self):
            self.closed = True

    injected = ClosableFakeRedis()
    store = RedisTenantStore(client=injected)

    await store.close()

    assert injected.closed is True


# ----------------------------------------------------------------------
# delete() (CP-4)
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_store_delete_removes_mapping(patched_redis):
    store = RedisTenantStore(url="redis://fake")
    await store.set("t1", "store-1")

    await store.delete("t1")

    assert await store.get("t1") is None


@pytest.mark.asyncio
async def test_model_registry_delete_removes_mapping(patched_redis):
    reg = RedisModelRegistry(url="redis://fake")
    await reg.set("t1", "model-1")

    await reg.delete("t1")

    assert await reg.get("t1") is None

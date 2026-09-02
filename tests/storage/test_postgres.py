"""
Tests for the asyncpg-backed storage classes.

asyncpg is a real dependency in this environment, but spinning up Postgres
for a unit test is overkill. We replace ``create_pool`` with a fake that
returns an in-memory pool so the storage logic itself is exercised.
"""

from contextlib import asynccontextmanager

import pytest

from py_authz.core.exceptions import ConfigurationError
from py_authz.storage import postgres as pg_module
from py_authz.storage.postgres import PostgresModelRegistry, PostgresTenantStore


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, query, *args):
        self.pool.executes.append((query, args))
        self.pool._apply_execute(query, args)

    async def fetchrow(self, query, *args):
        self.pool.fetches.append((query, args))
        return self.pool._apply_fetch(query, args)

    async def fetch(self, query, *args):
        self.pool.fetches.append((query, args))
        return self.pool._apply_fetch_all(query, args)


class FakePool:
    def __init__(self):
        self.executes: list[tuple[str, tuple]] = []
        self.fetches: list[tuple[str, tuple]] = []
        self.tenants: dict[str, str] = {}
        self.tenant_models: dict[str, str] = {}
        self.closed = False
        self.acquire_timeouts: list[float | None] = []

    @asynccontextmanager
    async def acquire(self, timeout=None):
        self.acquire_timeouts.append(timeout)
        yield FakeConnection(self)

    async def close(self):
        self.closed = True

    def _apply_execute(self, query, args):
        if "INSERT INTO tenants" in query:
            tenant_id, store_id = args
            self.tenants[tenant_id] = store_id
        elif "INSERT INTO tenant_models" in query:
            tenant_id, model_id = args
            self.tenant_models[tenant_id] = model_id

    def _apply_fetch(self, query, args):
        if "FROM tenants" in query:
            store_id = self.tenants.get(args[0])
            return {"store_id": store_id} if store_id is not None else None
        if "FROM tenant_models" in query:
            model_id = self.tenant_models.get(args[0])
            return {"model_id": model_id} if model_id is not None else None
        return None

    def _apply_fetch_all(self, query, args):
        if "FROM tenants" in query:
            return [{"tenant_id": tid} for tid in sorted(self.tenants)]
        return []


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()
    pool.create_pool_calls = 0
    pool.create_pool_kwargs = None

    async def _create_pool(dsn, **kwargs):
        pool.create_pool_calls += 1
        pool.create_pool_kwargs = kwargs
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(pg_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_tenant_store_connect_and_round_trip(patched_asyncpg):
    store = PostgresTenantStore(dsn="postgres://fake")
    await store.connect()

    await store.set("t1", "store-1")

    assert await store.get("t1") == "store-1"


@pytest.mark.asyncio
async def test_tenant_store_get_returns_none_when_missing(patched_asyncpg):
    store = PostgresTenantStore(dsn="postgres://fake")
    await store.connect()

    assert await store.get("missing") is None


@pytest.mark.asyncio
async def test_tenant_store_set_uses_upsert(patched_asyncpg):
    store = PostgresTenantStore(dsn="postgres://fake")
    await store.connect()

    await store.set("t1", "store-1")
    await store.set("t1", "store-2")

    assert patched_asyncpg.tenants["t1"] == "store-2"
    # sanity: upsert query is the one being executed
    assert "ON CONFLICT" in patched_asyncpg.executes[0][0]


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids(patched_asyncpg):
    store = PostgresTenantStore(dsn="postgres://fake")
    await store.connect()

    await store.set("t2", "store-2")
    await store.set("t1", "store-1")

    assert await store.list_tenant_ids() == ["t1", "t2"]


@pytest.mark.asyncio
async def test_model_registry_round_trip(patched_asyncpg):
    reg = PostgresModelRegistry(dsn="postgres://fake")
    await reg.connect()

    await reg.set("t1", "model-1")

    assert await reg.get("t1") == "model-1"


@pytest.mark.asyncio
async def test_model_registry_get_returns_none_when_missing(patched_asyncpg):
    reg = PostgresModelRegistry(dsn="postgres://fake")
    await reg.connect()

    assert await reg.get("missing") is None


@pytest.mark.parametrize("cls", [PostgresTenantStore, PostgresModelRegistry])
class TestConnectionLifecycle:
    """
    REL-3: both Postgres-backed stores share the same connect/close/
    context-manager/not-connected-guard contract — exercise it once,
    parametrized over both classes, instead of duplicating it per class.
    """

    @pytest.mark.asyncio
    async def test_connect_is_idempotent(self, cls, patched_asyncpg):
        store = cls(dsn="postgres://fake")

        await store.connect()
        await store.connect()

        assert patched_asyncpg.create_pool_calls == 1

    @pytest.mark.asyncio
    async def test_close_releases_pool(self, cls, patched_asyncpg):
        store = cls(dsn="postgres://fake")
        await store.connect()

        await store.close()

        assert patched_asyncpg.closed is True
        assert store._pool is None

    @pytest.mark.asyncio
    async def test_close_without_connect_is_a_noop(self, cls, patched_asyncpg):
        store = cls(dsn="postgres://fake")

        await store.close()  # must not raise

        assert patched_asyncpg.closed is False

    @pytest.mark.asyncio
    async def test_get_before_connect_raises_configuration_error(self, cls, patched_asyncpg):
        store = cls(dsn="postgres://fake")

        with pytest.raises(ConfigurationError, match="not connected"):
            await store.get("t1")

    @pytest.mark.asyncio
    async def test_set_before_connect_raises_configuration_error(self, cls, patched_asyncpg):
        store = cls(dsn="postgres://fake")

        with pytest.raises(ConfigurationError, match="not connected"):
            await store.set("t1", "x")

    @pytest.mark.asyncio
    async def test_async_context_manager_connects_and_closes(self, cls, patched_asyncpg):
        async with cls(dsn="postgres://fake") as store:
            assert store._pool is patched_asyncpg

        assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids_before_connect_raises(patched_asyncpg):
    store = PostgresTenantStore(dsn="postgres://fake")

    with pytest.raises(ConfigurationError, match="not connected"):
        await store.list_tenant_ids()


# ----------------------------------------------------------------------
# Regression coverage for REL2-11: pool sizing/timeouts were previously
# unset entirely — a Postgres instance under load, or a connection stuck
# after the initial handshake, could block a call indefinitely.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_tenant_store_forwards_pool_sizing_and_timeout(patched_asyncpg):
    store = PostgresTenantStore(
        dsn="postgres://fake", pool_min_size=2, pool_max_size=5, command_timeout=3.0
    )
    await store.connect()

    assert patched_asyncpg.create_pool_kwargs == {
        "min_size": 2,
        "max_size": 5,
        "command_timeout": 3.0,
    }

    await store.get("t1")
    assert patched_asyncpg.acquire_timeouts == [3.0]


@pytest.mark.asyncio
async def test_model_registry_forwards_pool_sizing_and_timeout(patched_asyncpg):
    registry = PostgresModelRegistry(
        dsn="postgres://fake", pool_min_size=1, pool_max_size=3, command_timeout=2.5
    )
    await registry.connect()

    assert patched_asyncpg.create_pool_kwargs == {
        "min_size": 1,
        "max_size": 3,
        "command_timeout": 2.5,
    }

    await registry.get("t1")
    assert patched_asyncpg.acquire_timeouts == [2.5]

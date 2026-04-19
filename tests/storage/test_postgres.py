"""
Tests for the asyncpg-backed storage classes.

asyncpg is a real dependency in this environment, but spinning up Postgres
for a unit test is overkill. We replace ``create_pool`` with a fake that
returns an in-memory pool so the storage logic itself is exercised.
"""

from contextlib import asynccontextmanager

import pytest

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


class FakePool:
    def __init__(self):
        self.executes: list[tuple[str, tuple]] = []
        self.fetches: list[tuple[str, tuple]] = []
        self.tenants: dict[str, str] = {}
        self.tenant_models: dict[str, str] = {}

    @asynccontextmanager
    async def acquire(self):
        yield FakeConnection(self)

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


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn):
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

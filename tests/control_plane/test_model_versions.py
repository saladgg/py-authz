"""Tests for py_authz.control_plane.model_versions.ModelVersionStore (CP-6)."""

from contextlib import asynccontextmanager

import pytest

from py_authz.control_plane import model_versions as mv_module
from py_authz.control_plane.model_versions import ModelVersionStore
from py_authz.core.exceptions import ConfigurationError


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def fetchrow(self, query, *args):
        return self.pool._apply(query, args)

    async def fetch(self, query, *args):
        return self.pool._apply_fetch_all(query, args)


class FakePool:
    def __init__(self):
        self.rows: list[dict] = []
        self._counter = 0
        self.closed = False

    @asynccontextmanager
    async def acquire(self, timeout=None):
        yield FakeConnection(self)

    async def close(self):
        self.closed = True

    def _apply(self, query, args):
        if "INSERT INTO model_versions" in query:
            tenant_id, model_id, schema_json, change_summary, created_by = args
            self._counter += 1
            row = {
                "id": self._counter,
                "tenant_id": tenant_id,
                "model_id": model_id,
                "schema_json": schema_json,
                "change_summary": change_summary,
                "created_by": created_by,
                "created_at": self._counter,
            }
            self.rows.append(row)
            return row
        if "SELECT * FROM model_versions WHERE id" in query:
            (version_id,) = args
            return next((r for r in self.rows if r["id"] == version_id), None)
        return None

    def _apply_fetch_all(self, query, args):
        if "tenant_id IS NULL" in query:
            limit, offset = args
            rows = [r for r in self.rows if r["tenant_id"] is None]
        else:
            tenant_id, limit, offset = args
            rows = [r for r in self.rows if r["tenant_id"] == tenant_id]
        rows = sorted(rows, key=lambda r: r["created_at"], reverse=True)
        return rows[offset : offset + limit]


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn, **kwargs):
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(mv_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_record_and_get_round_trip(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()

    version = await store.record(
        tenant_id="t1",
        model_id="model-1",
        schema_json={"schema_version": "1.1", "type_definitions": []},
        change_summary="initial sync",
        created_by="user:admin",
    )

    fetched = await store.get(version.id)
    assert fetched.model_id == "model-1"
    assert fetched.schema_json == {"schema_version": "1.1", "type_definitions": []}
    assert fetched.change_summary == "initial sync"


@pytest.mark.asyncio
async def test_history_is_newest_first_and_scoped_to_tenant(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()

    await store.record(
        tenant_id="t1", model_id="m1", schema_json={}, change_summary=None, created_by=None
    )
    await store.record(
        tenant_id="t1", model_id="m2", schema_json={}, change_summary=None, created_by=None
    )
    await store.record(
        tenant_id="t2", model_id="m3", schema_json={}, change_summary=None, created_by=None
    )

    history = await store.history("t1")

    assert [v.model_id for v in history] == ["m2", "m1"]


@pytest.mark.asyncio
async def test_get_unknown_version_returns_none(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()

    assert await store.get(999) is None


@pytest.mark.asyncio
async def test_history_with_no_tenant_filter_returns_the_global_history(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()

    await store.record(
        tenant_id=None, model_id="m1", schema_json={}, change_summary=None, created_by=None
    )
    await store.record(
        tenant_id="t1", model_id="m2", schema_json={}, change_summary=None, created_by=None
    )

    history = await store.history(None)

    assert [v.model_id for v in history] == ["m1"]


# -------------------------------------------------------------------
# connect()/close()/context-manager/_require_pool — connection lifecycle
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()
    pool_after_first_connect = store._pool

    await store.connect()

    assert store._pool is pool_after_first_connect


@pytest.mark.asyncio
async def test_close_clears_the_pool(patched_asyncpg):
    store = ModelVersionStore(dsn="postgres://fake")
    await store.connect()

    await store.close()

    assert store._pool is None
    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_close_without_ever_connecting_is_a_noop():
    store = ModelVersionStore(dsn="postgres://fake")

    await store.close()

    assert store._pool is None


@pytest.mark.asyncio
async def test_used_as_an_async_context_manager(patched_asyncpg):
    async with ModelVersionStore(dsn="postgres://fake") as store:
        version = await store.record(
            tenant_id="t1", model_id="m1", schema_json={}, change_summary=None, created_by=None
        )
        assert version.model_id == "m1"

    assert store._pool is None


@pytest.mark.asyncio
async def test_operations_before_connect_raise_configuration_error():
    store = ModelVersionStore(dsn="postgres://fake")

    with pytest.raises(ConfigurationError, match="not connected"):
        await store.get(1)

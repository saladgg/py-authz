"""Tests for py_authz.storage.schema.apply_schema()."""

from contextlib import asynccontextmanager

import pytest

from py_authz.storage import schema as schema_module


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, sql):
        self.pool.executed_sql.append(sql)


class FakePool:
    def __init__(self):
        self.executed_sql: list[str] = []
        self.closed = False

    @asynccontextmanager
    async def acquire(self):
        yield FakeConnection(self)

    async def close(self):
        self.closed = True


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn):
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(schema_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_apply_schema_executes_every_schema_file_in_order(patched_asyncpg):
    await schema_module.apply_schema("postgres://fake")

    assert len(patched_asyncpg.executed_sql) == len(schema_module.SCHEMA_FILES)
    # Each file's content actually reaches the connection, in the declared
    # order (tenants, then tenant_models, then audit_logs) — order matters
    # because a later file is allowed to reference an earlier table.
    assert "CREATE TABLE IF NOT EXISTS tenants" in patched_asyncpg.executed_sql[0]
    assert "CREATE TABLE IF NOT EXISTS tenant_models" in patched_asyncpg.executed_sql[1]
    assert "CREATE TABLE IF NOT EXISTS audit_logs" in patched_asyncpg.executed_sql[2]


@pytest.mark.asyncio
async def test_apply_schema_closes_its_own_pool(patched_asyncpg):
    await schema_module.apply_schema("postgres://fake")

    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_apply_schema_closes_pool_even_if_execute_raises(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn):
        return pool

    class _BoomConnection(FakeConnection):
        async def execute(self, sql):
            raise RuntimeError("boom")

    @asynccontextmanager
    async def _acquire(self):
        yield _BoomConnection(self)

    monkeypatch.setattr(FakePool, "acquire", _acquire)
    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(schema_module, "asyncpg", fake_module)

    with pytest.raises(RuntimeError, match="boom"):
        await schema_module.apply_schema("postgres://fake")

    assert pool.closed is True


def test_schema_sql_files_exist_on_disk():
    for filename in schema_module.SCHEMA_FILES:
        path = schema_module._SQL_DIR / filename
        assert path.is_file(), f"missing schema file: {path}"
        assert path.read_text().strip()

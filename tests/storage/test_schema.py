"""Tests for py_authz.storage.schema.apply_schema()."""

import pytest

from py_authz.storage import schema as schema_module


class FakeConnection:
    """`apply_schema()` uses one connection (REL3-14 — it used to open a
    whole default-sized pool to run DDL on one connection)."""

    def __init__(self):
        self.executed_sql: list[str] = []
        self.closed = False
        self.fail = False

    async def execute(self, sql):
        if self.fail:
            raise RuntimeError("boom")
        self.executed_sql.append(sql)

    async def close(self):
        self.closed = True


@pytest.fixture
def patched_asyncpg(monkeypatch):
    conn = FakeConnection()

    async def _connect(dsn):
        return conn

    def _no_pools(*a, **kw):
        raise AssertionError("apply_schema must not open a pool")

    fake_module = type(
        "asyncpg_stub",
        (),
        {"connect": staticmethod(_connect), "create_pool": staticmethod(_no_pools)},
    )
    monkeypatch.setattr(schema_module, "asyncpg", fake_module)
    return conn


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
async def test_apply_schema_closes_its_own_connection(patched_asyncpg):
    await schema_module.apply_schema("postgres://fake")

    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_apply_schema_closes_its_connection_even_if_execute_raises(patched_asyncpg):
    patched_asyncpg.fail = True

    with pytest.raises(RuntimeError):
        await schema_module.apply_schema("postgres://fake")

    assert patched_asyncpg.closed is True

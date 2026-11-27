"""Tests for py_authz.storage.schema (the REL3-10 migration runner)."""

from contextlib import asynccontextmanager
from datetime import UTC, datetime

import pytest

from py_authz.storage import schema as schema_module


class FakeConnection:
    """Records statements; models `schema_migrations` and the advisory lock."""

    def __init__(self):
        self.executed: list[str] = []
        self.applied: dict[str, datetime] = {}
        self.table_exists = False
        self.closed = False
        self.fail_on: str | None = None
        self.lock_free_after = 0  # failed try-lock attempts before success
        self.lock_attempts = 0
        self.invalid_indexes: set[str] = set()
        self.in_transaction = False
        self.transactional: list[str] = []

    async def execute(self, sql, *args):
        if self.fail_on and self.fail_on in sql:
            raise RuntimeError("boom")
        if sql.startswith("INSERT INTO schema_migrations"):
            self.applied[args[0]] = datetime(2026, 11, 26, tzinfo=UTC)
            return
        if "CREATE TABLE IF NOT EXISTS schema_migrations" in sql:
            self.table_exists = True
        self.executed.append(sql)
        if self.in_transaction:
            self.transactional.append(sql)

    async def fetchval(self, sql, *args):
        if "pg_try_advisory_lock" in sql:
            self.lock_attempts += 1
            return self.lock_attempts > self.lock_free_after
        if "indisvalid" in sql:
            return True if args[0] in self.invalid_indexes else None
        if "to_regclass" in sql:
            return self.table_exists
        raise AssertionError(sql)

    async def fetch(self, sql):
        return [{"version": v, "applied_at": t} for v, t in self.applied.items()]

    @asynccontextmanager
    async def transaction(self):
        self.in_transaction = True
        try:
            yield
        finally:
            self.in_transaction = False

    async def close(self):
        self.closed = True


@pytest.fixture
def conn(monkeypatch):
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


ALL_VERSIONS = [f.removesuffix(".sql") for f in schema_module.SCHEMA_FILES]


@pytest.mark.asyncio
async def test_applies_every_file_in_order_and_records_it(conn):
    applied = await schema_module.apply_schema("postgres://fake")

    assert applied == ALL_VERSIONS
    assert list(conn.applied) == ALL_VERSIONS
    ddl = [s for s in conn.executed if "schema_migrations" not in s and "advisory" not in s]
    assert "CREATE TABLE IF NOT EXISTS tenants" in ddl[0]
    assert "CREATE TABLE IF NOT EXISTS tenant_models" in ddl[1]
    assert "CREATE TABLE IF NOT EXISTS audit_logs" in ddl[2]
    assert conn.executed[-1].startswith("SELECT pg_advisory_unlock")


@pytest.mark.asyncio
async def test_second_run_applies_nothing(conn):
    await schema_module.apply_schema("postgres://fake")
    conn.executed.clear()

    assert await schema_module.apply_schema("postgres://fake") == []
    assert not any("CREATE INDEX" in s for s in conn.executed)


@pytest.mark.asyncio
async def test_no_transaction_files_run_statement_by_statement_outside_a_transaction(conn):
    await schema_module.apply_schema("postgres://fake")

    concurrent = [s for s in conn.executed if "CONCURRENTLY" in s]
    # 0008 (one index) and 0010 (two), each as its own statement.
    assert len(concurrent) == 3
    assert all(s.count("CREATE INDEX") == 1 for s in concurrent)
    assert not any("CONCURRENTLY" in s for s in conn.transactional)
    # Ordinary files run inside a transaction.
    assert any("ADD COLUMN IF NOT EXISTS store_id" in s for s in conn.transactional)


@pytest.mark.asyncio
async def test_an_invalid_index_from_a_failed_build_is_dropped_first(conn):
    conn.invalid_indexes = {"idx_audit_logs_user_timestamp"}

    await schema_module.apply_schema("postgres://fake")

    drop = conn.executed.index('DROP INDEX CONCURRENTLY IF EXISTS "idx_audit_logs_user_timestamp"')
    create = next(
        i
        for i, s in enumerate(conn.executed)
        if s.startswith("CREATE INDEX") and "idx_audit_logs_user_timestamp" in s
    )
    assert drop < create


@pytest.mark.asyncio
async def test_waits_for_the_advisory_lock(conn):
    conn.lock_free_after = 2

    await schema_module.apply_schema("postgres://fake", poll_interval=0.001)

    assert conn.lock_attempts == 3


@pytest.mark.asyncio
async def test_lock_timeout_raises_and_closes(conn):
    conn.lock_free_after = 10**9

    with pytest.raises(schema_module.SchemaLockTimeout):
        await schema_module.apply_schema("postgres://fake", lock_timeout=0.01, poll_interval=0.001)

    assert conn.closed is True
    assert conn.applied == {}


@pytest.mark.asyncio
async def test_failure_unlocks_closes_and_records_only_what_succeeded(conn):
    conn.fail_on = "ADD COLUMN IF NOT EXISTS store_id"

    with pytest.raises(RuntimeError):
        await schema_module.apply_schema("postgres://fake")

    assert conn.closed is True
    assert conn.executed[-1].startswith("SELECT pg_advisory_unlock")
    assert "0009_audit_logs_store_id" not in conn.applied
    assert "0008_audit_logs_timestamp_idx" in conn.applied


@pytest.mark.asyncio
async def test_status_without_the_table_reports_everything_pending(conn):
    states = await schema_module.schema_status("postgres://fake")

    assert [s.version for s in states] == ALL_VERSIONS
    assert not any(s.applied for s in states)
    assert conn.closed is True
    assert await schema_module.pending_migrations("postgres://fake") == ALL_VERSIONS


@pytest.mark.asyncio
async def test_status_after_apply_reports_nothing_pending(conn):
    await schema_module.apply_schema("postgres://fake")

    assert await schema_module.pending_migrations("postgres://fake") == []


def test_split_statements_ignores_comments_and_blank_parts():
    sql = "-- py-authz: no-transaction\n-- a; comment\nCREATE A;\n\nCREATE B;\n"

    assert schema_module._split_statements(sql) == ["CREATE A", "CREATE B"]


def test_every_bundled_file_exists_and_concurrent_ones_are_marked():
    for filename in schema_module.SCHEMA_FILES:
        sql = (schema_module._SQL_DIR / filename).read_text()
        if "CONCURRENTLY" in sql:
            assert schema_module._is_no_transaction(sql), filename

"""Tests for py_authz.audit.postgres.PostgresAuditQuery (CP-5)."""

import json
from contextlib import asynccontextmanager
from datetime import datetime

import pytest

from py_authz.audit import postgres as audit_pg_module
from py_authz.audit.postgres import PostgresAuditQuery
from py_authz.core.exceptions import ConfigurationError


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def fetch(self, query, *args):
        self.pool.fetch_calls.append((query, args))
        return self.pool.rows


class FakePool:
    def __init__(self, rows=None):
        self.rows = rows or []
        self.fetch_calls: list[tuple[str, tuple]] = []
        self.closed = False
        self.acquire_timeouts: list[float | None] = []

    @asynccontextmanager
    async def acquire(self, timeout=None):
        self.acquire_timeouts.append(timeout)
        yield FakeConnection(self)

    async def close(self):
        self.closed = True


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn, **kwargs):
        pool.create_pool_kwargs = kwargs
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(audit_pg_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_query_before_connect_raises_configuration_error():
    query = PostgresAuditQuery(dsn="postgres://fake")
    with pytest.raises(ConfigurationError):
        await query.query()


@pytest.mark.asyncio
async def test_query_with_no_filters_has_no_where_clause(patched_asyncpg):
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    await query.query()

    sql, params = patched_asyncpg.fetch_calls[0]
    assert "WHERE" not in sql
    assert "ORDER BY" in sql
    assert params == (50, 0)  # default limit, offset


@pytest.mark.asyncio
async def test_query_ands_every_given_filter(patched_asyncpg):
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    since = datetime(2026, 1, 1)
    until = datetime(2026, 2, 1)

    await query.query(
        tenant_id="t1",
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=True,
        since=since,
        until=until,
        limit=10,
        offset=5,
    )

    sql, params = patched_asyncpg.fetch_calls[0]
    assert sql.count(" AND ") == 6  # 7 conditions ANDed together
    assert params == ("t1", "user:1", "view", "document:1", True, since, until, 10, 5)


@pytest.mark.asyncio
async def test_query_decodes_reason_data_json(patched_asyncpg):
    patched_asyncpg.rows = [
        {
            "id": 1,
            "timestamp": datetime(2026, 1, 1),
            "tenant_id": "t1",
            "user_id": "user:1",
            "action": "view",
            "resource": "document:1",
            "allowed": True,
            "reason": "cache hit",
            "reason_data": json.dumps({"cache_hit": True}),
            "request_id": "req-1",
        }
    ]
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    results = await query.query()

    assert results[0]["reason_data"] == {"cache_hit": True}


@pytest.mark.asyncio
async def test_query_leaves_null_reason_data_as_none(patched_asyncpg):
    patched_asyncpg.rows = [
        {
            "id": 1,
            "timestamp": datetime(2026, 1, 1),
            "tenant_id": None,
            "user_id": "user:1",
            "action": "view",
            "resource": "document:1",
            "allowed": False,
            "reason": None,
            "reason_data": None,
            "request_id": None,
        }
    ]
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    results = await query.query()

    assert results[0]["reason_data"] is None


@pytest.mark.asyncio
async def test_forwards_pool_sizing_and_timeout(patched_asyncpg):
    query = PostgresAuditQuery(
        dsn="postgres://fake", pool_min_size=2, pool_max_size=4, command_timeout=1.5
    )
    await query.connect()

    assert patched_asyncpg.create_pool_kwargs == {
        "min_size": 2,
        "max_size": 4,
        "command_timeout": 1.5,
    }

    await query.query()
    assert patched_asyncpg.acquire_timeouts == [1.5]


@pytest.mark.asyncio
async def test_context_manager_connects_and_closes(patched_asyncpg):
    async with PostgresAuditQuery(dsn="postgres://fake") as query:
        await query.query()

    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg, monkeypatch):
    calls = 0
    create_pool = audit_pg_module.asyncpg.create_pool

    async def _counting_create_pool(dsn, **kwargs):
        nonlocal calls
        calls += 1
        return await create_pool(dsn, **kwargs)

    monkeypatch.setattr(audit_pg_module.asyncpg, "create_pool", _counting_create_pool)
    query = PostgresAuditQuery(dsn="postgres://fake")

    await query.connect()
    await query.connect()

    assert calls == 1


@pytest.mark.asyncio
async def test_close_without_connect_is_a_noop(patched_asyncpg):
    query = PostgresAuditQuery(dsn="postgres://fake")

    await query.close()  # must not raise

    assert patched_asyncpg.closed is False


@pytest.mark.asyncio
async def test_close_releases_the_pool_so_queries_fail_until_reconnect(patched_asyncpg):
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    await query.close()

    assert patched_asyncpg.closed is True
    with pytest.raises(ConfigurationError):
        await query.query()


@pytest.mark.asyncio
async def test_legacy_store_id_matches_pre_0009_rows(patched_asyncpg):
    """ARCH3-16: old rows held the store id in `tenant_id` and no `store_id`."""
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()

    await query.query(tenant_id="acme", legacy_store_id="store-1", store_id="store-1")

    sql, params = patched_asyncpg.fetch_calls[0]
    assert "(tenant_id = $1 OR (store_id IS NULL AND tenant_id = $2))" in sql
    assert "store_id = $3" in sql
    assert params[:3] == ("acme", "store-1", "store-1")


@pytest.mark.asyncio
async def test_before_adds_a_keyset_condition(patched_asyncpg):
    """REL3-15: keyset pagination on ("timestamp", id)."""
    query = PostgresAuditQuery(dsn="postgres://fake")
    await query.connect()
    ts = datetime(2026, 1, 1)

    await query.query(user_id="user:1", before=(ts, 42), limit=10)

    sql, params = patched_asyncpg.fetch_calls[0]
    assert '("timestamp", id) < ($2, $3)' in sql
    assert params == ("user:1", ts, 42, 10, 0)


def test_cursor_round_trips_and_rejects_garbage():
    from datetime import UTC

    from py_authz.audit.postgres import decode_cursor, encode_cursor
    from py_authz.core.exceptions import InvalidAuthzRequest

    ts = datetime(2026, 1, 1, 12, 30, tzinfo=UTC)
    assert decode_cursor(encode_cursor(ts, 7)) == (ts, 7)
    for bad in ("!!!", encode_cursor(ts, 7)[:-4], "bm90LWEtY3Vyc29y"):
        with pytest.raises(InvalidAuthzRequest):
            decode_cursor(bad)

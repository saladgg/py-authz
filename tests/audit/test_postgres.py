import json
from contextlib import asynccontextmanager
from datetime import datetime

import pytest

from py_authz.audit import postgres as audit_pg_module
from py_authz.audit.postgres import PostgresAuditLogger
from py_authz.audit.types import AuditEvent
from py_authz.core.exceptions import ConfigurationError


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def copy_records_to_table(self, table, *, columns, records, timeout=None):
        self.pool.copies.append((table, tuple(columns), list(records), timeout))


class FakePool:
    def __init__(self):
        self.copies: list[tuple[str, tuple, list, float | None]] = []
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
    pool.create_pool_calls = 0
    pool.create_pool_kwargs = None

    async def _create_pool(dsn, **kwargs):
        pool.create_pool_calls += 1
        pool.create_pool_kwargs = kwargs
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(audit_pg_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_connect_creates_pool(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")
    await logger.connect()

    assert logger._pool is patched_asyncpg


@pytest.mark.asyncio
async def test_connect_passes_command_timeout_to_pool(patched_asyncpg):
    """
    Regression test for REL2-4: previously `create_pool()`/`pool.
    acquire()` had no timeout at all, so a hung Postgres connection could
    block a write (and its background task — see
    `AuthzEngine._dispatch_audit_event`) forever.
    """
    logger = PostgresAuditLogger(dsn="postgres://fake", command_timeout=3.5)
    await logger.connect()

    assert patched_asyncpg.create_pool_kwargs["command_timeout"] == 3.5

    event = AuditEvent(
        timestamp=datetime(2026, 4, 18, 12, 0, 0),
        tenant_id="t1",
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=True,
        reason=None,
        reason_data=None,
        request_id=None,
    )
    await logger.log(event)

    assert patched_asyncpg.acquire_timeouts == [3.5]
    assert patched_asyncpg.copies[0][3] == 3.5


@pytest.mark.asyncio
async def test_log_executes_insert_with_event_fields(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")
    await logger.connect()

    ts = datetime(2026, 4, 18, 12, 0, 0)
    event = AuditEvent(
        timestamp=ts,
        tenant_id="tenant-1",
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=True,
        reason="allowed via relation 'view'",
        reason_data={"cache_hit": False},
        request_id="req-1",
        store_id="store-1",
    )

    await logger.log(event)

    assert len(patched_asyncpg.copies) == 1
    table, columns, records, _ = patched_asyncpg.copies[0]
    assert table == "audit_logs"
    # `reason_data` must be JSON-serialized before binding — the
    # `audit_logs.reason_data` column is `jsonb` and asyncpg does not
    # auto-encode a Python dict into JSON on its own (REL-4).
    assert dict(zip(columns, records[0], strict=True)) == {
        "timestamp": ts,
        "tenant_id": "tenant-1",
        "store_id": "store-1",
        "user_id": "user:1",
        "action": "view",
        "resource": "document:1",
        "allowed": True,
        "reason": "allowed via relation 'view'",
        "reason_data": json.dumps({"cache_hit": False}),
        "request_id": "req-1",
    }


@pytest.mark.asyncio
async def test_log_many_writes_one_copy_for_the_whole_batch(patched_asyncpg):
    """REL3-16: a batch is one round trip, not one INSERT per event."""
    logger = PostgresAuditLogger(dsn="postgres://fake")
    await logger.connect()
    events = [
        AuditEvent(
            timestamp=datetime(2026, 4, 18, 12, 0, i),
            tenant_id="t",
            user_id=f"user:{i}",
            action="view",
            resource="document:1",
            allowed=True,
        )
        for i in range(3)
    ]

    await logger.log_many(events)
    await logger.log_many([])

    assert len(patched_asyncpg.copies) == 1
    assert [r[3] for r in patched_asyncpg.copies[0][2]] == ["user:0", "user:1", "user:2"]


@pytest.mark.asyncio
async def test_log_preserves_none_reason_data(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")
    await logger.connect()

    event = AuditEvent(
        timestamp=datetime(2026, 4, 18, 12, 0, 0),
        tenant_id=None,
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=False,
        reason=None,
        reason_data=None,
        request_id=None,
    )

    await logger.log(event)

    _, columns, records, _ = patched_asyncpg.copies[0]
    # `None` stays `None` (a genuinely absent value), not the string "null".
    assert records[0][columns.index("reason_data")] is None


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")

    await logger.connect()
    await logger.connect()

    assert patched_asyncpg.create_pool_calls == 1


@pytest.mark.asyncio
async def test_close_releases_pool(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")
    await logger.connect()

    await logger.close()

    assert patched_asyncpg.closed is True
    assert logger._pool is None


@pytest.mark.asyncio
async def test_close_without_connect_is_a_noop(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")

    await logger.close()  # must not raise

    assert patched_asyncpg.closed is False


@pytest.mark.asyncio
async def test_log_before_connect_raises_configuration_error(patched_asyncpg):
    logger = PostgresAuditLogger(dsn="postgres://fake")

    event = AuditEvent(
        timestamp=datetime(2026, 4, 18, 12, 0, 0),
        tenant_id="tenant-1",
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=True,
        reason=None,
        reason_data=None,
        request_id=None,
    )

    with pytest.raises(ConfigurationError, match="not connected"):
        await logger.log(event)


@pytest.mark.asyncio
async def test_async_context_manager_connects_and_closes(patched_asyncpg):
    async with PostgresAuditLogger(dsn="postgres://fake") as logger:
        assert logger._pool is patched_asyncpg

    assert patched_asyncpg.closed is True

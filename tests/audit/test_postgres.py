from contextlib import asynccontextmanager
from datetime import datetime

import pytest

from py_authz.audit import postgres as audit_pg_module
from py_authz.audit.postgres import PostgresAuditLogger
from py_authz.audit.types import AuditEvent


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def execute(self, query, *args):
        self.pool.executes.append((query, args))


class FakePool:
    def __init__(self):
        self.executes: list[tuple[str, tuple]] = []

    @asynccontextmanager
    async def acquire(self):
        yield FakeConnection(self)


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn):
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
    )

    await logger.log(event)

    assert len(patched_asyncpg.executes) == 1
    query, args = patched_asyncpg.executes[0]
    assert "INSERT INTO audit_logs" in query
    assert args == (
        ts,
        "tenant-1",
        "user:1",
        "view",
        "document:1",
        True,
        "allowed via relation 'view'",
        {"cache_hit": False},
        "req-1",
    )

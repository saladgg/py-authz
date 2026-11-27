"""Tests for py_authz.control_plane.operators.OperatorStore (CP-2)."""

from contextlib import asynccontextmanager

import pytest

from py_authz.control_plane import operators as operators_module
from py_authz.control_plane.operators import OperatorStore
from py_authz.core.exceptions import ConfigurationError


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def fetchrow(self, query, *args):
        return self.pool._apply(query, args)

    async def fetch(self, query, *args):
        return sorted(self.pool.rows.values(), key=lambda r: r["created_at"])


class FakePool:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self._counter = 0
        self.closed = False

    @asynccontextmanager
    async def acquire(self, timeout=None):
        yield FakeConnection(self)

    async def close(self):
        self.closed = True

    def _apply(self, query, args):
        subject, email = args
        self._counter += 1
        existing = self.rows.get(subject)
        row = {
            "id": existing["id"] if existing else self._counter,
            "subject": subject,
            "email": email or (existing["email"] if existing else None),
            "created_at": existing["created_at"] if existing else self._counter,
        }
        self.rows[subject] = row
        return row


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn, **kwargs):
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(operators_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_record_login_creates_a_new_operator(patched_asyncpg):
    store = OperatorStore(dsn="postgres://fake")
    await store.connect()

    op = await store.record_login(subject="alice", email="alice@example.com")

    assert op.subject == "alice"
    assert op.email == "alice@example.com"


@pytest.mark.asyncio
async def test_record_login_is_idempotent_for_the_same_subject(patched_asyncpg):
    store = OperatorStore(dsn="postgres://fake", login_interval=0)
    await store.connect()

    first = await store.record_login(subject="alice", email="alice@example.com")
    second = await store.record_login(subject="alice", email="alice@example.com")

    assert first.id == second.id
    assert len(await store.list()) == 1


@pytest.mark.asyncio
async def test_record_login_keeps_existing_email_when_new_one_is_none(patched_asyncpg):
    store = OperatorStore(dsn="postgres://fake", login_interval=0)
    await store.connect()

    await store.record_login(subject="alice", email="alice@example.com")
    updated = await store.record_login(subject="alice", email=None)

    assert updated.email == "alice@example.com"


@pytest.mark.asyncio
async def test_record_login_is_throttled_per_subject_and_email(patched_asyncpg):
    """REL3-19: `/auth/me` runs on every page load; don't upsert each time."""
    now = [1000.0]
    store = OperatorStore(dsn="postgres://fake", login_interval=60, clock=lambda: now[0])
    await store.connect()

    assert await store.record_login(subject="alice", email="a@x") is not None
    assert await store.record_login(subject="alice", email="a@x") is None
    # A changed email is written straight away; so is another subject.
    assert await store.record_login(subject="alice", email="new@x") is not None
    assert await store.record_login(subject="bob", email=None) is not None
    now[0] += 61
    assert await store.record_login(subject="alice", email="new@x") is not None


@pytest.mark.asyncio
async def test_recent_login_memory_is_bounded(patched_asyncpg, monkeypatch):
    from py_authz.control_plane import operators as operators_module

    monkeypatch.setattr(operators_module, "_RECENT_LOGINS_MAX", 2)
    store = OperatorStore(dsn="postgres://fake")
    await store.connect()
    for name in ("a", "b", "c"):
        await store.record_login(subject=name, email=None)

    assert list(store._recent_logins) == ["b", "c"]


# -------------------------------------------------------------------
# connect()/close()/context-manager/_require_pool — connection lifecycle
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg):
    store = OperatorStore(dsn="postgres://fake")
    await store.connect()
    pool_after_first_connect = store._pool

    await store.connect()

    assert store._pool is pool_after_first_connect


@pytest.mark.asyncio
async def test_close_clears_the_pool(patched_asyncpg):
    store = OperatorStore(dsn="postgres://fake")
    await store.connect()

    await store.close()

    assert store._pool is None
    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_close_without_ever_connecting_is_a_noop():
    store = OperatorStore(dsn="postgres://fake")

    await store.close()

    assert store._pool is None


@pytest.mark.asyncio
async def test_used_as_an_async_context_manager(patched_asyncpg):
    async with OperatorStore(dsn="postgres://fake") as store:
        op = await store.record_login(subject="alice", email="alice@example.com")
        assert op.subject == "alice"

    assert store._pool is None


@pytest.mark.asyncio
async def test_operations_before_connect_raise_configuration_error():
    store = OperatorStore(dsn="postgres://fake")

    with pytest.raises(ConfigurationError, match="not connected"):
        await store.list()

"""Tests for py_authz.control_plane.service_accounts.ServiceAccountStore (CP-3)."""

from contextlib import asynccontextmanager

import asyncpg
import pytest

from py_authz.control_plane import service_accounts as sa_module
from py_authz.control_plane.security import verify_secret
from py_authz.control_plane.service_accounts import ServiceAccountStore
from py_authz.core.exceptions import ConfigurationError, InvalidAuthzRequest


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def fetchrow(self, query, *args):
        self.pool.calls.append((query, args))
        return self.pool._apply(query, args)

    async def fetch(self, query, *args):
        self.pool.calls.append((query, args))
        rows = sorted(self.pool.rows.values(), key=lambda r: r["created_at"], reverse=True)
        return rows

    async def execute(self, query, *args):
        self.pool.calls.append((query, args))
        self.pool._apply(query, args)


class FakePool:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.calls: list[tuple[str, tuple]] = []
        self.closed = False
        self._counter = 0

    @asynccontextmanager
    async def acquire(self, timeout=None):
        yield FakeConnection(self)

    async def close(self):
        self.closed = True

    def _apply(self, query, args):
        if "INSERT INTO service_accounts" in query:
            account_id, name, description, secret_hash, scopes, created_by = args
            if any(r["name"] == name and r["revoked_at"] is None for r in self.rows.values()):
                raise sa_module.asyncpg.UniqueViolationError("duplicate name")
            self._counter += 1
            row = {
                "id": account_id,
                "name": name,
                "description": description,
                "secret_hash": secret_hash,
                "scopes": scopes,
                "created_by": created_by,
                "created_at": self._counter,
                "last_used_at": None,
                "revoked_at": None,
            }
            self.rows[account_id] = row
            return row
        if "UPDATE service_accounts" in query and "SET revoked_at" in query:
            # Matches revoke()'s SQL — checked before the rotate-only
            # branch below since revoke()'s SQL also mentions
            # "secret_hash" (it invalidates the hash too, see CP-17).
            account_id, secret_hash = args
            row = self.rows.get(account_id)
            if row is not None:
                row["revoked_at"] = "now"
                row["secret_hash"] = secret_hash
            return None
        if "UPDATE service_accounts" in query and "secret_hash" in query:
            # rotate()'s SQL: sets secret_hash only, guarded by
            # `revoked_at IS NULL` in the WHERE clause (not a SET).
            account_id, secret_hash = args
            row = self.rows.get(account_id)
            if row is None or row["revoked_at"] is not None:
                return None
            row["secret_hash"] = secret_hash
            return row
        if "UPDATE service_accounts" in query and "last_used_at" in query:
            (account_id,) = args
            row = self.rows.get(account_id)
            if row is not None:
                row["last_used_at"] = "now"
            return None
        if "SELECT * FROM service_accounts WHERE id" in query:
            (account_id,) = args
            return self.rows.get(account_id)
        return None


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn, **kwargs):
        return pool

    fake_module = type(
        "asyncpg_stub",
        (),
        {
            "create_pool": staticmethod(_create_pool),
            "UniqueViolationError": asyncpg.UniqueViolationError,
        },
    )
    monkeypatch.setattr(sa_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_create_returns_account_and_verifiable_secret(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()

    account, secret = await store.create(
        name="ci-bot", description="CI pipeline", scopes=["models:sync"], created_by="user:admin"
    )

    assert account.name == "ci-bot"
    assert account.scopes == ["models:sync"]
    assert verify_secret(secret, account.secret_hash) is True
    assert account.secret_hash != secret  # never the plaintext


@pytest.mark.asyncio
async def test_create_rejects_duplicate_active_name(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()

    await store.create(name="ci-bot", description=None, scopes=[], created_by=None)

    with pytest.raises(InvalidAuthzRequest):
        await store.create(name="ci-bot", description=None, scopes=[], created_by=None)


@pytest.mark.asyncio
async def test_get_returns_none_for_unknown_id(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()

    assert await store.get("sa_missing") is None


@pytest.mark.asyncio
async def test_revoke_is_idempotent_and_sets_revoked_at(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    account, _ = await store.create(name="ci-bot", description=None, scopes=[], created_by=None)

    await store.revoke(account.id)
    await store.revoke(account.id)  # must not raise

    refetched = await store.get(account.id)
    assert refetched.is_revoked is True


@pytest.mark.asyncio
async def test_revoke_invalidates_the_secret_hash_itself(patched_asyncpg):
    """
    CP-17: a rotated/revoked secret's hash must actually be invalidated,
    not just `revoked_at` set while the old hash remains verifiable —
    defense in depth for any future code path that checks
    `verify_secret()` without also checking `is_revoked`.
    """
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    account, original_secret = await store.create(
        name="ci-bot", description=None, scopes=[], created_by=None
    )

    await store.revoke(account.id)

    refetched = await store.get(account.id)
    assert refetched.secret_hash != account.secret_hash
    assert verify_secret(original_secret, refetched.secret_hash) is False


@pytest.mark.asyncio
async def test_rotate_issues_a_new_secret_invalidating_the_old_one(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    account, old_secret = await store.create(
        name="ci-bot", description=None, scopes=[], created_by=None
    )

    rotated, new_secret = await store.rotate(account.id)

    assert rotated.id == account.id
    assert new_secret != old_secret
    assert verify_secret(new_secret, rotated.secret_hash) is True
    assert verify_secret(old_secret, rotated.secret_hash) is False


@pytest.mark.asyncio
async def test_rotate_rejects_revoked_account(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    account, _ = await store.create(name="ci-bot", description=None, scopes=[], created_by=None)
    await store.revoke(account.id)

    with pytest.raises(InvalidAuthzRequest):
        await store.rotate(account.id)


@pytest.mark.asyncio
async def test_operations_before_connect_raise_configuration_error():
    store = ServiceAccountStore(dsn="postgres://fake")
    with pytest.raises(ConfigurationError):
        await store.get("sa_1")


@pytest.mark.asyncio
async def test_list_returns_every_account_including_revoked(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    active, _ = await store.create(name="ci-bot", description=None, scopes=[], created_by=None)
    revoked, _ = await store.create(name="old-bot", description=None, scopes=[], created_by=None)
    await store.revoke(revoked.id)

    accounts = await store.list()

    assert {a.id for a in accounts} == {active.id, revoked.id}
    assert next(a for a in accounts if a.id == revoked.id).is_revoked is True


@pytest.mark.asyncio
async def test_touch_last_used_sets_the_timestamp(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    account, _ = await store.create(name="ci-bot", description=None, scopes=[], created_by=None)
    assert account.last_used_at is None

    await store.touch_last_used(account.id)

    refreshed = await store.get(account.id)
    assert refreshed.last_used_at == "now"


# -------------------------------------------------------------------
# connect()/close()/context-manager — connection lifecycle
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()
    pool_after_first_connect = store._pool

    await store.connect()

    assert store._pool is pool_after_first_connect


@pytest.mark.asyncio
async def test_close_clears_the_pool(patched_asyncpg):
    store = ServiceAccountStore(dsn="postgres://fake")
    await store.connect()

    await store.close()

    assert store._pool is None
    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_close_without_ever_connecting_is_a_noop():
    store = ServiceAccountStore(dsn="postgres://fake")

    await store.close()

    assert store._pool is None


@pytest.mark.asyncio
async def test_used_as_an_async_context_manager(patched_asyncpg):
    async with ServiceAccountStore(dsn="postgres://fake") as store:
        account, _ = await store.create(name="ci-bot", description=None, scopes=[], created_by=None)
        assert account.name == "ci-bot"

    assert store._pool is None

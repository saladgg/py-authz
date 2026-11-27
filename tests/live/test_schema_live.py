"""
Live tests for the migration runner (REL3-10), the store_id column
(ARCH3-16), keyset audit paging (REL3-15) and COPY batching (REL3-16),
each against a throwaway database on the real Postgres.
"""

import asyncio
import json
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import asyncpg
import pytest

from py_authz.audit.batching import BatchingAuditLogger
from py_authz.audit.postgres import PostgresAuditLogger, PostgresAuditQuery
from py_authz.audit.types import AuditEvent
from py_authz.storage import schema
from tests.live.conftest import requires_postgres

pytestmark = requires_postgres


@pytest.fixture
async def fresh_dsn(postgres_dsn):
    name = f"py_authz_schema_{uuid.uuid4().hex[:12]}"
    admin = await asyncpg.connect(postgres_dsn)
    try:
        await admin.execute(f'CREATE DATABASE "{name}"')
    finally:
        await admin.close()
    parts = urlsplit(postgres_dsn)
    try:
        yield urlunsplit(parts._replace(path=f"/{name}"))
    finally:
        admin = await asyncpg.connect(postgres_dsn)
        try:
            await admin.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        finally:
            await admin.close()


ALL = [f.removesuffix(".sql") for f in schema.SCHEMA_FILES]


@pytest.mark.asyncio
async def test_concurrent_runners_apply_each_migration_once(fresh_dsn):
    results = await asyncio.gather(
        *(schema.apply_schema(fresh_dsn, poll_interval=0.05) for _ in range(4))
    )

    # Exactly one runner did the work; the others waited and found nothing.
    assert sorted(results, key=len) == [[], [], [], ALL]
    assert await schema.pending_migrations(fresh_dsn) == []
    conn = await asyncpg.connect(fresh_dsn)
    try:
        invalid = await conn.fetchval("SELECT count(*) FROM pg_index WHERE NOT indisvalid")
        # The lock was released.
        assert await conn.fetchval("SELECT pg_try_advisory_lock($1)", schema.SCHEMA_LOCK_KEY)
    finally:
        await conn.close()
    assert invalid == 0


@pytest.mark.asyncio
async def test_upgrade_from_an_unversioned_database_keeps_legacy_rows_findable(fresh_dsn):
    # A pre-REL3-10 database: 0001-0008 applied by the old runner, no
    # schema_migrations table, and an audit row with the store id in
    # tenant_id.
    conn = await asyncpg.connect(fresh_dsn)
    try:
        for filename in schema.SCHEMA_FILES[:8]:
            sql = (schema._SQL_DIR / filename).read_text()
            for stmt in schema._split_statements(sql):
                await conn.execute(stmt)
        await conn.execute(
            "INSERT INTO audit_logs (timestamp, tenant_id, user_id, action, resource, allowed) "
            "VALUES (now() - interval '1 day', 'store-old', 'user:a', 'view', 'doc:1', true)"
        )
    finally:
        await conn.close()

    assert await schema.apply_schema(fresh_dsn) == ALL

    async with PostgresAuditLogger(fresh_dsn, pool_min_size=1, pool_max_size=1) as writer:
        await writer.log(
            AuditEvent(
                timestamp=datetime.now(UTC),
                tenant_id="acme",
                store_id="store-new",
                user_id="user:a",
                action="view",
                resource="doc:1",
                allowed=True,
            )
        )
    async with PostgresAuditQuery(fresh_dsn, pool_min_size=1, pool_max_size=1) as q:
        both = await q.query(tenant_id="acme", legacy_store_id="store-old")
        new_only = await q.query(tenant_id="acme")
        by_store = await q.query(store_id="store-new")

    assert [r["store_id"] for r in both] == ["store-new", None]
    assert len(new_only) == 1 and new_only[0]["tenant_id"] == "acme"
    assert len(by_store) == 1


@pytest.mark.asyncio
async def test_an_invalid_index_from_a_failed_concurrent_build_is_rebuilt(fresh_dsn):
    await schema.apply_schema(fresh_dsn)
    conn = await asyncpg.connect(fresh_dsn)
    try:
        # Simulate a concurrent build that died: a UNIQUE build over
        # duplicate rows fails and leaves an INVALID index of that name.
        await conn.execute("DROP INDEX idx_audit_logs_user_timestamp")
        await conn.execute(
            "INSERT INTO audit_logs (timestamp, user_id, action, resource, allowed) "
            "SELECT now(), 'user:dup', 'view', 'doc:1', true FROM generate_series(1, 2)"
        )
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                "CREATE UNIQUE INDEX CONCURRENTLY idx_audit_logs_user_timestamp "
                "ON audit_logs (user_id)"
            )
        await conn.execute(
            "DELETE FROM schema_migrations WHERE version = '0010_audit_logs_filter_indexes'"
        )

        assert await schema.apply_schema(fresh_dsn) == ["0010_audit_logs_filter_indexes"]

        valid, definition = await conn.fetchrow(
            "SELECT i.indisvalid, pg_get_indexdef(i.indexrelid) FROM pg_index i "
            "JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE c.relname = 'idx_audit_logs_user_timestamp'"
        )
    finally:
        await conn.close()
    assert valid is True
    assert "UNIQUE" not in definition and '"timestamp" DESC' in definition


@pytest.mark.asyncio
async def test_batched_copy_writes_and_keyset_pages(fresh_dsn):
    await schema.apply_schema(fresh_dsn)
    base = datetime(2026, 11, 1, tzinfo=UTC)
    # Two rows share a timestamp, so paging relies on the id tiebreak.
    stamps = [base, base + timedelta(seconds=1), base + timedelta(seconds=1), base]
    stamps.append(datetime.now())  # naive, as AuthzEngine produces

    async with BatchingAuditLogger(
        PostgresAuditLogger(fresh_dsn, pool_min_size=1, pool_max_size=1), flush_interval=0.05
    ) as logger:
        for i, ts in enumerate(stamps):
            await logger.log(
                AuditEvent(
                    timestamp=ts,
                    tenant_id="acme",
                    store_id="s1",
                    user_id="user:p",
                    action="view",
                    resource=f"doc:{i}",
                    allowed=True,
                    reason_data={"i": i},
                )
            )

    async with PostgresAuditQuery(fresh_dsn, pool_min_size=1, pool_max_size=1) as q:
        everything = await q.query(user_id="user:p", limit=100)
        paged, before = [], None
        while True:
            page = await q.query(user_id="user:p", limit=2, before=before)
            paged += page
            if len(page) < 2:
                break
            before = (page[-1]["timestamp"], page[-1]["id"])

    assert len(everything) == 5
    assert [r["id"] for r in paged] == [r["id"] for r in everything]
    assert sorted(r["reason_data"]["i"] for r in everything) == [0, 1, 2, 3, 4]
    assert json.dumps(everything[0]["reason_data"])  # decoded jsonb

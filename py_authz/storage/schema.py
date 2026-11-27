"""
Bundled schema for the Postgres-backed storage classes
(`PostgresTenantStore`, `PostgresModelRegistry`, `PostgresAuditLogger`)
and the control-plane API's own tables.

A small forward-only migration runner (REL3-10):

- `schema_migrations(version, applied_at)` records which files have run,
  so each file runs once per database instead of on every boot.
- A Postgres advisory lock serialises runners, so two replicas booting
  together don't race on catalog entries. The lock is taken with
  `pg_try_advisory_lock` in a poll loop, not a blocking
  `pg_advisory_lock`: a session blocked inside a statement would hold a
  snapshot open, and `CREATE INDEX CONCURRENTLY` in the lock holder waits
  for every such snapshot to end.
- A file whose first line is `-- py-authz: no-transaction` runs outside a
  transaction, one statement at a time. That's required for
  `CREATE INDEX CONCURRENTLY`, which builds an index on a large table
  without blocking writes. If an earlier concurrent build failed and left
  an INVALID index behind, it's dropped and rebuilt (`IF NOT EXISTS`
  would otherwise skip it forever).
- Every other file runs in one transaction together with its
  `schema_migrations` row, so it's either fully applied and recorded or
  not at all.

Every file is still written to be idempotent (`IF NOT EXISTS`), so a
database created before `schema_migrations` existed simply records the
files it already has on the first run.

Run it from a deploy step with `py-authz db migrate` (or call
`apply_schema()` yourself), and set `CONTROL_PLANE_APPLY_SCHEMA=false` in
production so replicas don't run DDL as they boot. Adopters with their own
migration tool (Alembic, sqlx, a SQL runbook) can apply the files in
`SCHEMA_FILES` order instead.
"""

import logging
import re
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import anyio
import asyncpg

from py_authz.core.exceptions import ExternalServiceError

logger = logging.getLogger("py_authz.storage.schema")

_SQL_DIR = Path(__file__).parent / "sql"

#: Applied in this order. 0004 onward back the control-plane API
#: (`py_authz/control_plane/`); they share one Postgres database with
#: 0001-0003, so `apply_schema()` stays the one call that gets a database
#: ready, control-plane tables included.
SCHEMA_FILES = (
    "0001_tenants.sql",
    "0002_tenant_models.sql",
    "0003_audit_logs.sql",
    "0004_operators.sql",
    "0005_service_accounts.sql",
    "0006_model_versions.sql",
    "0007_control_plane_jobs.sql",
    "0008_audit_logs_timestamp_idx.sql",
    "0009_audit_logs_store_id.sql",
    "0010_audit_logs_filter_indexes.sql",
)

#: First line that marks a file as "run outside a transaction".
NO_TRANSACTION_MARKER = "-- py-authz: no-transaction"

#: Arbitrary, fixed advisory-lock key for schema migrations ("pyauthz"
#: in ASCII). Any process using the same key waits for the others.
SCHEMA_LOCK_KEY = 0x7079617574687A

_CREATE_MIGRATIONS_TABLE = """
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
)
"""

_CONCURRENT_INDEX_RE = re.compile(
    r"CREATE\s+(?:UNIQUE\s+)?INDEX\s+CONCURRENTLY\s+IF\s+NOT\s+EXISTS\s+(\w+)",
    re.IGNORECASE,
)


class SchemaLockTimeout(ExternalServiceError):
    """Another process held the schema-migration lock for too long."""


@dataclass(frozen=True)
class MigrationState:
    """One bundled migration file and when (if ever) it was applied."""

    version: str
    applied_at: datetime | None

    @property
    def applied(self) -> bool:
        return self.applied_at is not None


def _version(filename: str) -> str:
    return filename.removesuffix(".sql")


def _is_no_transaction(sql: str) -> bool:
    return sql.lstrip().startswith(NO_TRANSACTION_MARKER)


def _split_statements(sql: str) -> list[str]:
    """
    Split a no-transaction file into single statements. Postgres runs a
    multi-statement simple query as one implicit transaction, which
    `CREATE INDEX CONCURRENTLY` refuses. Bundled files keep semicolons out
    of comments and string literals, which is all this needs to handle.
    """
    lines = [line for line in sql.splitlines() if not line.lstrip().startswith("--")]
    return [stmt.strip() for stmt in "\n".join(lines).split(";") if stmt.strip()]


async def _acquire_lock(conn, *, timeout: float, poll_interval: float) -> None:
    deadline = time.monotonic() + timeout
    while not await conn.fetchval("SELECT pg_try_advisory_lock($1)", SCHEMA_LOCK_KEY):
        if time.monotonic() >= deadline:
            raise SchemaLockTimeout(
                f"Timed out after {timeout:.0f}s waiting for the schema-migration lock; "
                "another process is applying migrations"
            )
        await anyio.sleep(poll_interval)


async def _drop_invalid_indexes(conn, sql: str) -> None:
    """Drop any INVALID index (left by a failed concurrent build) this file creates."""
    for name in _CONCURRENT_INDEX_RE.findall(sql):
        invalid = await conn.fetchval(
            "SELECT NOT i.indisvalid FROM pg_index i "
            "JOIN pg_class c ON c.oid = i.indexrelid "
            "WHERE c.relname = $1 AND pg_catalog.pg_table_is_visible(c.oid)",
            name,
        )
        if invalid:
            logger.warning("dropping invalid index %s left by an earlier failed build", name)
            # `name` comes from a bundled SQL file, never from user input.
            await conn.execute(f'DROP INDEX CONCURRENTLY IF EXISTS "{name}"')


async def _apply_file(conn, filename: str) -> None:
    sql = (_SQL_DIR / filename).read_text()
    version = _version(filename)
    record = "INSERT INTO schema_migrations (version) VALUES ($1)"
    if _is_no_transaction(sql):
        await _drop_invalid_indexes(conn, sql)
        for statement in _split_statements(sql):
            await conn.execute(statement)
        await conn.execute(record, version)
    else:
        async with conn.transaction():
            await conn.execute(sql)
            await conn.execute(record, version)


async def apply_schema(
    dsn: str,
    *,
    lock_timeout: float = 300.0,
    poll_interval: float = 0.5,
) -> list[str]:
    """
    Apply every bundled migration `dsn` hasn't recorded yet, in order.

    Opens and closes its own single connection (REL3-14), takes the
    schema advisory lock first (waiting up to `lock_timeout` seconds,
    then raising `SchemaLockTimeout`), and releases it before returning.

    Returns:
        The versions applied by this call (empty when already up to date).
    """
    conn = await asyncpg.connect(dsn)
    try:
        await _acquire_lock(conn, timeout=lock_timeout, poll_interval=poll_interval)
        try:
            await conn.execute(_CREATE_MIGRATIONS_TABLE)
            done = {r["version"] for r in await conn.fetch("SELECT version FROM schema_migrations")}
            applied: list[str] = []
            for filename in SCHEMA_FILES:
                version = _version(filename)
                if version in done:
                    continue
                logger.info("applying schema migration %s", version)
                await _apply_file(conn, filename)
                applied.append(version)
            return applied
        finally:
            await conn.execute("SELECT pg_advisory_unlock($1)", SCHEMA_LOCK_KEY)
    finally:
        await conn.close()


async def schema_status(dsn: str) -> list[MigrationState]:
    """
    Every bundled migration with its `applied_at`, or `None` if pending.
    Read-only: doesn't create `schema_migrations` (a database without it
    reports every migration as pending).
    """
    conn = await asyncpg.connect(dsn)
    try:
        exists = await conn.fetchval("SELECT to_regclass('schema_migrations') IS NOT NULL")
        applied: dict[str, datetime] = {}
        if exists:
            rows = await conn.fetch("SELECT version, applied_at FROM schema_migrations")
            applied = {r["version"]: r["applied_at"] for r in rows}
    finally:
        await conn.close()
    return [
        MigrationState(version=_version(f), applied_at=applied.get(_version(f)))
        for f in SCHEMA_FILES
    ]


async def pending_migrations(dsn: str) -> list[str]:
    """Versions of bundled migrations `dsn` hasn't recorded as applied."""
    return [m.version for m in await schema_status(dsn) if not m.applied]

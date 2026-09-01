"""
Bundled schema for the Postgres-backed storage classes
(`PostgresTenantStore`, `PostgresModelRegistry`, `PostgresAuditLogger`).

This is NOT a full migration framework — no version tracking, no
up/down migrations, no diffing. It's the minimum needed to go from
"nothing" to "these three tables exist" in one call, shipped as real,
versioned SQL files instead of a docstring comment. Each file is
idempotent (`CREATE TABLE IF NOT EXISTS`/`CREATE INDEX IF NOT EXISTS`),
so `apply_schema()` is safe to run more than once.

For a real production deployment, prefer applying this (or your own
adapted version of it) through whatever migration tool the rest of your
stack already uses (Alembic, sqlx, a plain SQL runbook, ...) rather than
calling `apply_schema()` at application startup — DDL is usually a
deliberate, reviewed deploy step, not something to run implicitly every
time a process boots. `apply_schema()` exists for getting a fresh
dev/test database ready quickly.
"""

from pathlib import Path

import asyncpg

_SQL_DIR = Path(__file__).parent / "sql"

#: Applied in this order — later files may (in principle) reference
#: earlier tables, though none currently do.
SCHEMA_FILES = (
    "0001_tenants.sql",
    "0002_tenant_models.sql",
    "0003_audit_logs.sql",
)


async def apply_schema(dsn: str) -> None:
    """
    Create every table these storage classes need against `dsn`, if it
    doesn't already exist. Opens and closes its own connection pool —
    doesn't require an existing `PostgresTenantStore`/etc. instance.
    """
    pool = await asyncpg.create_pool(dsn)
    try:
        async with pool.acquire() as conn:
            for filename in SCHEMA_FILES:
                sql = (_SQL_DIR / filename).read_text()
                await conn.execute(sql)
    finally:
        await pool.close()

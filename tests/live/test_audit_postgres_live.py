"""
Live test for PostgresAuditLogger against a real Postgres instance.

This is the specific regression test for REL-4: the mocked suite can only
prove `json.dumps()` was called before binding, not that asyncpg/Postgres
actually accepts and round-trips the result as `jsonb`. Before the fix,
passing a raw Python dict as the `reason_data` bind parameter raised
`asyncpg.exceptions.DataError` on the very first real write.
"""

from datetime import UTC, datetime

import asyncpg
import pytest

from py_authz.audit.postgres import PostgresAuditLogger
from py_authz.audit.types import AuditEvent
from tests.live.conftest import requires_postgres

pytestmark = requires_postgres


@pytest.mark.asyncio
async def test_log_writes_jsonb_reason_data(postgres_dsn, postgres_schema):
    ts = datetime(2026, 4, 18, 12, 0, 0, tzinfo=UTC)
    event = AuditEvent(
        timestamp=ts,
        tenant_id="acme",
        user_id="user:1",
        action="view",
        resource="document:1",
        allowed=True,
        reason="allowed via relation 'view'",
        reason_data={"cache_hit": False, "checked_relations": ["viewer", "editor"]},
        request_id="req-1",
    )

    async with PostgresAuditLogger(dsn=postgres_dsn) as logger:
        await logger.log(event)

    conn = await asyncpg.connect(postgres_dsn)
    try:
        row = await conn.fetchrow(
            "SELECT tenant_id, allowed, reason_data FROM audit_logs WHERE request_id = $1",
            "req-1",
        )
    finally:
        await conn.close()

    assert row is not None
    assert row["tenant_id"] == "acme"
    assert row["allowed"] is True
    # asyncpg decodes a `jsonb` column back into a Python object, so a
    # round trip through the real driver confirms the value was stored
    # as actual JSON, not the string repr of a Python dict.
    import json

    assert json.loads(row["reason_data"]) == {
        "cache_hit": False,
        "checked_relations": ["viewer", "editor"],
    }


@pytest.mark.asyncio
async def test_log_preserves_none_reason_data(postgres_dsn, postgres_schema):
    event = AuditEvent(
        timestamp=datetime(2026, 4, 18, 12, 0, 0, tzinfo=UTC),
        tenant_id=None,
        user_id="user:2",
        action="view",
        resource="document:2",
        allowed=False,
        reason=None,
        reason_data=None,
        request_id="req-2",
    )

    async with PostgresAuditLogger(dsn=postgres_dsn) as logger:
        await logger.log(event)

    conn = await asyncpg.connect(postgres_dsn)
    try:
        row = await conn.fetchrow(
            "SELECT reason_data FROM audit_logs WHERE request_id = $1",
            "req-2",
        )
    finally:
        await conn.close()

    assert row["reason_data"] is None

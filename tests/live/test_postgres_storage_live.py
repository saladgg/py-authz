"""
Live tests for PostgresTenantStore / PostgresModelRegistry against a real
Postgres instance.

The mocked suite (tests/storage/test_postgres.py) exercises the query
logic against a fake `asyncpg`; this suite exists to catch anything a fake
pool can't — real asyncpg parameter binding, real `ON CONFLICT` upsert
behavior, and connection lifecycle against an actual server.
"""

import pytest

from py_authz.core.exceptions import ConfigurationError
from py_authz.storage.postgres import PostgresModelRegistry, PostgresTenantStore
from tests.live.conftest import requires_postgres

pytestmark = requires_postgres


@pytest.mark.asyncio
async def test_tenant_store_round_trip_and_upsert(postgres_dsn, postgres_schema):
    async with PostgresTenantStore(dsn=postgres_dsn) as store:
        assert await store.get("acme") is None

        await store.set("acme", "store-1")
        assert await store.get("acme") == "store-1"

        # ON CONFLICT DO UPDATE — re-setting an existing tenant_id updates
        # in place rather than raising a duplicate-key error.
        await store.set("acme", "store-2")
        assert await store.get("acme") == "store-2"


@pytest.mark.asyncio
async def test_tenant_store_list_tenant_ids_is_sorted(postgres_dsn, postgres_schema):
    async with PostgresTenantStore(dsn=postgres_dsn) as store:
        await store.set("zeta", "store-z")
        await store.set("acme", "store-a")

        assert await store.list_tenant_ids() == ["acme", "zeta"]


@pytest.mark.asyncio
async def test_model_registry_round_trip(postgres_dsn, postgres_schema):
    async with PostgresModelRegistry(dsn=postgres_dsn) as reg:
        assert await reg.get("acme") is None

        await reg.set("acme", "01H-model-1")
        assert await reg.get("acme") == "01H-model-1"


@pytest.mark.asyncio
async def test_tenant_store_use_before_connect_raises(postgres_dsn, postgres_schema):
    store = PostgresTenantStore(dsn=postgres_dsn)

    with pytest.raises(ConfigurationError, match="not connected"):
        await store.get("acme")

"""
Fixtures shared by tests that talk to a REAL OpenFGA / Keycloak / Redis
instance rather than a mock.

This is the suite DX-9 in
`docs/todos/04_developer_experience_and_testing.md` calls for: nothing
elsewhere in this repo's tests ever exercises the actual HTTP/wire
response shapes these dependencies return — every other test mocks them.
That gap is exactly how bugs like ARCH-1 (`ModelSync` reading a field name
that only exists on OpenFGA's *write* response, never its *list*
response) and REL-1/REL-2 (`HybridTenantStore`/`RedisTenantStore`'s
signature and bytes-decoding mismatches) shipped undetected — each is
covered here specifically because a mock of the dependency was more
forgiving than the real thing.

Run via `make test-integration` (boots `docker-compose.yml`'s
`openfga`/`keycloak`/`redis`/`postgres` services, waits for them, then
runs this directory), or manually:

    docker compose up -d openfga keycloak redis postgres
    export FGA_API_URL=http://localhost:8082
    export KEYCLOAK_ISSUER=http://localhost:8081/realms/py-authz
    export KEYCLOAK_AUDIENCE=py-authz-demo
    export REDIS_URL=redis://localhost:6380/0
    export POSTGRES_DSN=postgres://py_authz:py_authz@localhost:5433/py_authz
    uv run pytest tests/live -q --no-cov

Every test here is skipped (not failed, not collected as an error) when
its required env var isn't set, so plain `pytest`/`make test` stays fast
and fully offline by default.
"""

import os

import pytest

from py_authz.clients.openfga import OpenFGAClient

FGA_API_URL = os.environ.get("FGA_API_URL")
KEYCLOAK_ISSUER = os.environ.get("KEYCLOAK_ISSUER")
KEYCLOAK_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", "py-authz-demo")
REDIS_URL = os.environ.get("REDIS_URL")
POSTGRES_DSN = os.environ.get("POSTGRES_DSN")

requires_openfga = pytest.mark.skipif(
    not FGA_API_URL,
    reason=(
        "Set FGA_API_URL to a running OpenFGA instance to run this test "
        "(see `make test-integration`)."
    ),
)

requires_keycloak = pytest.mark.skipif(
    not KEYCLOAK_ISSUER,
    reason=(
        "Set KEYCLOAK_ISSUER to a running Keycloak realm to run this test "
        "(see `make test-integration`)."
    ),
)

requires_redis = pytest.mark.skipif(
    not REDIS_URL,
    reason=(
        "Set REDIS_URL to a running Redis instance to run this test (see `make test-integration`)."
    ),
)

requires_postgres = pytest.mark.skipif(
    not POSTGRES_DSN,
    reason=(
        "Set POSTGRES_DSN to a running Postgres instance to run this test "
        "(see `make test-integration`)."
    ),
)


@pytest.fixture
def fga_api_url() -> str:
    assert FGA_API_URL is not None  # guaranteed by `requires_openfga`
    return FGA_API_URL


@pytest.fixture
async def live_client(fga_api_url):
    """
    A real `OpenFGAClient`, pointed at a fresh store created just for this
    test. One store per test keeps tests independent without needing any
    cleanup API (OpenFGA has none for deleting stores in most deployments).
    """
    client = OpenFGAClient(api_url=fga_api_url, store_id=None, model_id=None)
    try:
        client.store_id = await client.create_store(name="py-authz-live-test")
        yield client
    finally:
        await client.aclose()


@pytest.fixture
def postgres_dsn() -> str:
    assert POSTGRES_DSN is not None  # guaranteed by `requires_postgres`
    return POSTGRES_DSN


@pytest.fixture
async def postgres_schema(postgres_dsn):
    """
    Applies the bundled schema (`py_authz.storage.schema.apply_schema`)
    against the live database once, then truncates every table it owns
    after the test so tests stay independent without needing a
    throwaway database per test (Postgres, unlike OpenFGA, has no cheap
    per-test "create store" equivalent here).
    """
    import asyncpg

    from py_authz.storage.schema import apply_schema

    await apply_schema(postgres_dsn)
    try:
        yield
    finally:
        conn = await asyncpg.connect(postgres_dsn)
        try:
            await conn.execute(
                "TRUNCATE tenants, tenant_models, audit_logs, operators, "
                "service_accounts, model_versions, control_plane_jobs"
            )
        finally:
            await conn.close()

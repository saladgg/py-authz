"""Tests for py_authz.control_plane.routes.cache (CP-9): stats +
bulk invalidate, and the 503-not-a-crash behavior when no Redis cache is
configured for this deployment (`deps.get_redis_cache` -> `None`).

Uses the *real* `RedisCache` over an in-memory Redis stand-in with real
glob semantics (`tests/fake_redis.py`), populated by real `AuthzEngine`s
namespaced the way `MultiTenantAuthz` namespaces them (by store id). The
previous fake cache only recorded the fragment string it was handed, so
a test could assert the wrong fragment and pass — which is exactly how
SEC3-6 ("invalidate tenant" deleting nothing) shipped.
"""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.cache.redis import RedisCache
from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import cache as cache_routes
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthzError
from py_authz.core.tenant_store import InMemoryTenantStore
from py_authz.core.types import AuthzRequest, Identity, Resource
from tests.conftest import MockOpenFGAClient
from tests.fake_redis import FakeRedis

from .conftest import bearer

STORES = {"acme": "01HSTOREACME", "globex": "01HSTOREGLOBEX"}


@pytest.fixture
def redis_cache():
    return RedisCache(client=FakeRedis())


@pytest.fixture
async def tenant_store():
    store = InMemoryTenantStore()
    for tenant_id, store_id in STORES.items():
        await store.set(tenant_id, store_id)
    return store


async def _cache_decision(cache, store_id: str, user: str, doc: str) -> str:
    """Populate the cache exactly the way a tenant's engine does."""
    engine = AuthzEngine(
        fga_client=MockOpenFGAClient(allowed=True), cache=cache, cache_namespace=store_id
    )
    request = AuthzRequest(
        identity=Identity(id=user), action="viewer", resource=Resource(type="doc", id=doc)
    )
    await engine.enforce(request)
    return engine._scoped_cache_key(request)


@pytest.fixture
async def populated(redis_cache):
    keys = {}
    for tenant_id, store_id in STORES.items():
        for user in ("user:bob", "user:carol"):
            keys[(tenant_id, user)] = await _cache_decision(redis_cache, store_id, user, "1")
    return keys


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper, redis_cache, tenant_store):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(cache_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.redis_cache = redis_cache
    fastapi_app.state.tenant_store = tenant_store

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


async def _remaining(cache, keys) -> set:
    return {k for k, v in keys.items() if await cache.get(v) is not None}


async def _as_operator(rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))


@pytest.mark.asyncio
async def test_stats_requires_system_auditor(client, rbac_authz, populated):
    resp = client.get("/api/v1/cache/stats", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/cache/stats", headers=bearer())
    assert resp.status_code == 200
    assert resp.json() == {"key_count": 4}


@pytest.mark.asyncio
async def test_stats_503s_when_no_redis_configured(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    app.state.redis_cache = None

    resp = client.get("/api/v1/cache/stats", headers=bearer())

    assert resp.status_code == 503


@pytest.mark.asyncio
async def test_invalidate_requires_system_operator(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"key": "some-key"})

    assert resp.status_code == 403  # auditor isn't enough; operator+ is required


@pytest.mark.asyncio
async def test_invalidate_by_key(client, rbac_authz, redis_cache, populated):
    await _as_operator(rbac_authz)
    key = populated[("acme", "user:bob")]

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"key": key})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "key"}
    assert await _remaining(redis_cache, populated) == set(populated) - {("acme", "user:bob")}


@pytest.mark.asyncio
async def test_invalidate_by_tenant_id_deletes_exactly_that_tenants_decisions(
    client, rbac_authz, redis_cache, populated
):
    """Regression test for SEC3-6: this used to report `deleted: 3` from a
    fake while a real cache kept every key (matched on tenant id, keys are
    namespaced by store id)."""
    await _as_operator(rbac_authz)

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"tenant_id": "acme"})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "tenant", "deleted": 2}
    assert await _remaining(redis_cache, populated) == {
        ("globex", "user:bob"),
        ("globex", "user:carol"),
    }


@pytest.mark.asyncio
async def test_invalidate_by_user_scoped_to_tenant(client, rbac_authz, redis_cache, populated):
    await _as_operator(rbac_authz)

    resp = client.post(
        "/api/v1/cache/invalidate",
        headers=bearer(),
        json={"user_id": "user:bob", "tenant_id": "acme"},
    )

    assert resp.status_code == 200
    assert resp.json()["deleted"] == 1
    assert await _remaining(redis_cache, populated) == set(populated) - {("acme", "user:bob")}


@pytest.mark.asyncio
async def test_invalidate_by_user_across_every_tenant(client, rbac_authz, redis_cache, populated):
    await _as_operator(rbac_authz)

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"user_id": "user:bob"})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "user", "deleted": 2}
    assert await _remaining(redis_cache, populated) == {
        ("acme", "user:carol"),
        ("globex", "user:carol"),
    }


@pytest.mark.asyncio
async def test_invalidate_unknown_tenant_is_404(client, rbac_authz, redis_cache, populated):
    await _as_operator(rbac_authz)

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"tenant_id": "nope"})

    assert resp.status_code == 404
    assert await _remaining(redis_cache, populated) == set(populated)


@pytest.mark.asyncio
async def test_glob_metacharacters_cannot_widen_an_invalidation(
    client, rbac_authz, redis_cache, populated
):
    """`tenant_id="*"` used to wipe the whole cache; it's now just an
    unknown tenant, and a `*` user id matches nothing."""
    await _as_operator(rbac_authz)

    assert (
        client.post(
            "/api/v1/cache/invalidate", headers=bearer(), json={"tenant_id": "*"}
        ).status_code
        == 404
    )
    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"user_id": "*"})

    assert resp.json()["deleted"] == 0
    assert await _remaining(redis_cache, populated) == set(populated)


@pytest.mark.asyncio
async def test_invalidate_requires_at_least_one_field(client, rbac_authz):
    await _as_operator(rbac_authz)

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={})

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invalidate_503s_when_no_redis_configured(app, client, rbac_authz):
    await _as_operator(rbac_authz)
    app.state.redis_cache = None

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"key": "x"})

    assert resp.status_code == 503

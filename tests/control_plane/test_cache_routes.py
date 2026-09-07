"""Tests for py_authz.control_plane.routes.cache (CP-9): stats +
bulk invalidate, and the 503-not-a-crash behavior when no Redis cache is
configured for this deployment (`deps.get_redis_cache` -> `None`)."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import cache as cache_routes
from py_authz.core.exceptions import AuthzError
from py_authz.core.types import AuthzRequest, Identity

from .conftest import bearer


class FakeRedisCache:
    def __init__(self, *, key_count=0):
        self.key_count = key_count
        self.deleted_keys: list[str] = []
        self.deleted_fragments: list[str] = []

    async def count_keys(self):
        return self.key_count

    async def delete(self, key):
        self.deleted_keys.append(key)

    async def delete_by_fragment(self, fragment):
        self.deleted_fragments.append(fragment)
        return 3


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(cache_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.redis_cache = FakeRedisCache(key_count=42)

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


@pytest.mark.asyncio
async def test_stats_requires_system_auditor(client, rbac_authz):
    resp = client.get("/api/v1/cache/stats", headers=bearer())
    assert resp.status_code == 403

    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    resp = client.get("/api/v1/cache/stats", headers=bearer())
    assert resp.status_code == 200
    assert resp.json() == {"key_count": 42}


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
async def test_invalidate_by_key(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"key": "some-key"})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "key"}
    assert app.state.redis_cache.deleted_keys == ["some-key"]


@pytest.mark.asyncio
async def test_invalidate_by_user_id(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"user_id": "user:bob"})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "user", "deleted": 3}
    assert app.state.redis_cache.deleted_fragments == [AuthzRequest.identity_prefix("user:bob")]


@pytest.mark.asyncio
async def test_invalidate_by_user_id_scoped_to_tenant(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post(
        "/api/v1/cache/invalidate",
        headers=bearer(),
        json={"user_id": "user:bob", "tenant_id": "acme"},
    )

    assert resp.status_code == 200
    assert app.state.redis_cache.deleted_fragments == [
        f"acme:{AuthzRequest.identity_prefix('user:bob')}"
    ]


@pytest.mark.asyncio
async def test_invalidate_by_tenant_id(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"tenant_id": "acme"})

    assert resp.status_code == 200
    assert resp.json() == {"status": "invalidated", "mode": "tenant", "deleted": 3}
    assert app.state.redis_cache.deleted_fragments == ["acme:"]


@pytest.mark.asyncio
async def test_invalidate_requires_at_least_one_field(client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={})

    assert resp.status_code == 400


@pytest.mark.asyncio
async def test_invalidate_503s_when_no_redis_configured(app, client, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "operator", System(id=SYSTEM_OBJECT_ID))
    app.state.redis_cache = None

    resp = client.post("/api/v1/cache/invalidate", headers=bearer(), json={"key": "x"})

    assert resp.status_code == 503

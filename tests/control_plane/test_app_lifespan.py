"""
DX3-4: unit coverage for `control_plane/app.py`'s lifespan wiring.

The live suite (`tests/live/test_control_plane_live.py`) runs `_wire`
against real services; this covers the same code in the default offline
run by patching the store/client classes `app.py` constructs, so
construction order, cleanup registration and the Redis/no-Redis branches
are checked on every `make test`.
"""

import pytest
from starlette.testclient import TestClient

from py_authz.control_plane import app as app_module
from py_authz.control_plane.rate_limit import InMemoryRateLimiter, RedisRateLimiter
from py_authz.control_plane.settings import ControlPlaneSettings
from py_authz.core.locks import InProcessLockManager, RedisLockManager


class _Events(list):
    pass


@pytest.fixture
def events():
    return _Events()


@pytest.fixture
def patched(monkeypatch, events):
    """Replace every I/O-owning class `_wire` builds with a recorder."""

    def store_class(name, *, interrupted=0):
        class FakeStore:
            def __init__(self, dsn, **pool):
                self.dsn = dsn
                self.pool = pool

            async def connect(self):
                events.append(f"connect:{name}")

            async def close(self):
                events.append(f"close:{name}")

            async def ping(self):
                return None

            async def fail_interrupted(self):
                return interrupted

        FakeStore.__name__ = name
        return FakeStore

    for name in (
        "PostgresTenantStore",
        "PostgresModelRegistry",
        "PostgresAuditQuery",
        "ServiceAccountStore",
        "OperatorStore",
        "ModelVersionStore",
        "PostgresAuditLogger",
    ):
        monkeypatch.setattr(app_module, name, store_class(name))
    monkeypatch.setattr(app_module, "JobStore", store_class("JobStore", interrupted=2))

    async def fake_apply_schema(dsn):
        events.append("apply_schema")

    monkeypatch.setattr(app_module, "apply_schema", fake_apply_schema)

    class FakeModelSync:
        def __init__(self, client, *, model_factory):
            self.model = model_factory()

        async def sync(self):
            events.append("rbac_sync")
            return "rbac-model-1"

    monkeypatch.setattr(app_module, "ModelSync", FakeModelSync)

    class FakeRedis:
        async def aclose(self):
            events.append("close:redis")

        async def ping(self):
            return True

    monkeypatch.setattr(app_module, "redis_from_url", lambda url: FakeRedis())

    loaded = []
    monkeypatch.setattr(app_module, "load_module", loaded.append)
    return loaded


def _settings(**overrides):
    base = {
        "fga_api_url": "http://fga:8080",
        "rbac_fga_api_url": "http://fga:8080",
        "rbac_fga_store_id": "rbac-store",
        "postgres_dsn": "postgres://cp/cp",
        "oidc_issuer": "https://idp.example/realms/x",
        "oidc_audience": "cp",
    }
    base.update(overrides)
    return ControlPlaneSettings(**base)


def test_lifespan_wires_everything_and_tears_down_in_reverse(patched, events):
    settings = _settings(model_module="myapp.models", redis_url="redis://r:6379/0")
    app = app_module.create_app(settings)

    with TestClient(app) as client:
        state = app.state
        assert patched == ["myapp.models"]
        assert events[0] == "apply_schema"
        assert state.rbac_fga_client.model_id == "rbac-model-1"
        assert isinstance(state.service_account_rate_limiter, RedisRateLimiter)
        assert isinstance(state.tenant_manager.lock_manager, RedisLockManager)
        assert state.redis_cache is not None
        assert set(state.readiness_checks) == {"postgres", "openfga", "redis"}
        assert state.tenant_store.pool == {"pool_min_size": 1, "pool_max_size": 5}
        assert client.get("/livez").status_code == 200

    connects = [e.split(":", 1)[1] for e in events if e.startswith("connect:")]
    closes = [e.split(":", 1)[1] for e in events if e.startswith("close:") and e != "close:redis"]
    assert closes == list(reversed(connects))
    # Redis closes before the stores opened ahead of it.
    assert events.index("close:redis") < events.index("close:PostgresAuditLogger")


def test_lifespan_without_redis_uses_in_process_fallbacks(patched, events):
    settings = _settings(
        apply_schema_on_startup=False,
        rbac_fga_api_url="http://rbac-fga:8080",
    )
    app = app_module.create_app(settings)

    with TestClient(app):
        state = app.state
        assert "apply_schema" not in events
        assert patched == []
        assert isinstance(state.service_account_rate_limiter, InMemoryRateLimiter)
        assert isinstance(state.tenant_manager.lock_manager, InProcessLockManager)
        assert state.redis_cache is None
        assert set(state.readiness_checks) == {"postgres", "openfga", "openfga_rbac"}


def test_startup_failure_still_closes_what_was_opened(patched, events, monkeypatch):
    class FailingSync:
        def __init__(self, client, *, model_factory):
            pass

        async def sync(self):
            raise RuntimeError("rbac model rejected")

    monkeypatch.setattr(app_module, "ModelSync", FailingSync)
    app = app_module.create_app(_settings())

    with pytest.raises(RuntimeError, match="rbac model rejected"), TestClient(app):
        pass

    assert "close:PostgresTenantStore" in events
    assert "close:PostgresAuditLogger" in events

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

from py_authz.audit.batching import BatchingAuditLogger
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

    async def fake_pending_migrations(dsn):
        events.append("pending_migrations")
        return ["0010_audit_logs_filter_indexes"]

    monkeypatch.setattr(app_module, "pending_migrations", fake_pending_migrations)

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
        # REL3-16: decisions are batched in front of the Postgres writer.
        assert isinstance(state._audit_logger, BatchingAuditLogger)
        # REL3-19: a short-TTL RBAC decision cache, invalidated per identity.
        rbac_engine = state.rbac_authz._engine
        assert rbac_engine.cache is not None
        assert rbac_engine.cache_ttl == 5
        assert rbac_engine.invalidate_identity_on_write is True
        assert state.operator_store.pool["login_interval"] == 300
        assert "pending_migrations" not in events
        assert client.get("/livez").status_code == 200

    connects = [e.split(":", 1)[1] for e in events if e.startswith("connect:")]
    closes = [e.split(":", 1)[1] for e in events if e.startswith("close:") and e != "close:redis"]
    assert closes == list(reversed(connects))
    # Redis closes before the stores opened ahead of it.
    assert events.index("close:redis") < events.index("close:PostgresAuditLogger")


def test_lifespan_without_redis_uses_in_process_fallbacks(patched, events, caplog):
    settings = _settings(
        apply_schema_on_startup=False,
        rbac_fga_api_url="http://rbac-fga:8080",
        rbac_cache_ttl=0,
    )
    app = app_module.create_app(settings)

    with TestClient(app):
        state = app.state
        assert "apply_schema" not in events
        # REL3-10: with DDL off, boot checks and warns about pending migrations.
        assert "pending_migrations" in events
        assert state.rbac_authz._engine.cache is None
        assert "py-authz db migrate" in caplog.text
        assert "0010_audit_logs_filter_indexes" in caplog.text
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


def test_prometheus_metrics_endpoint_off_by_default(patched, events):
    app = app_module.create_app(_settings())

    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 404


def test_prometheus_metrics_endpoint_serves_text_format(patched, events):
    """REL3-24."""
    from py_authz.core.prometheus import PrometheusMetrics

    app = app_module.create_app(_settings(prometheus_metrics=True))

    with TestClient(app) as client:
        assert isinstance(app.state.metrics, PrometheusMetrics)
        client.get("/livez")
        resp = client.get("/metrics")

    assert resp.status_code == 200
    assert resp.headers["content-type"].startswith("text/plain")
    assert "py_authz_control_plane_requests_total" in resp.text
    assert "py_authz_control_plane_request_duration_ms_bucket" in resp.text


def test_prometheus_metrics_endpoint_checks_the_token(patched, events):
    app = app_module.create_app(_settings(prometheus_metrics=True, metrics_token="s3cret"))  # noqa: S106

    with TestClient(app) as client:
        assert client.get("/metrics").status_code == 401
        bad = client.get("/metrics", headers={"Authorization": "Bearer nope"})
        good = client.get("/metrics", headers={"Authorization": "Bearer s3cret"})

    assert bad.status_code == 401
    assert bad.headers["www-authenticate"] == "Bearer"
    assert good.status_code == 200


def test_clean_boot_logs_no_schema_or_interrupted_job_warnings(
    patched, events, monkeypatch, caplog
):
    """With DDL off, an up-to-date schema and no orphaned jobs, boot is
    quiet — neither warning fires."""

    async def no_pending(dsn):
        events.append("pending_migrations")
        return []

    async def none_interrupted(self):
        return 0

    monkeypatch.setattr(app_module, "pending_migrations", no_pending)
    monkeypatch.setattr(app_module.JobStore, "fail_interrupted", none_interrupted)
    app = app_module.create_app(_settings(apply_schema_on_startup=False))

    with caplog.at_level("WARNING"), TestClient(app):
        assert "pending_migrations" in events
        assert app.state.job_runner is not None

    assert "pending migration" not in caplog.text
    assert "interrupted control-plane job" not in caplog.text

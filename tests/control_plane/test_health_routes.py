"""Tests for py_authz.control_plane.routes.health (CP-10): the
unauthenticated `GET /health` probe and the `system#auditor`-gated
`GET /metrics` endpoint."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler
from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.control_plane.routes import health as health_routes
from py_authz.core.exceptions import AuthzError, ExternalServiceError
from py_authz.core.types import Identity

from .conftest import bearer


class FakeMetrics:
    def __init__(self, counters=None, durations=None):
        self.counters = counters or {}
        self.durations = durations or {}


def _check(*, fails=False, hangs=False):
    async def check():
        if hangs:
            import asyncio

            await asyncio.sleep(60)
        if fails:
            raise ExternalServiceError("openfga is down at http://10.0.0.7:8080 (secret detail)")

    return check


@pytest.fixture
def app(rbac_authz, oidc_validator, operator_store, bootstrapper):
    fastapi_app = FastAPI()
    fastapi_app.add_exception_handler(AuthzError, authz_error_handler)
    fastapi_app.include_router(health_routes.health_router)
    fastapi_app.include_router(health_routes.router, prefix="/api/v1")

    fastapi_app.state.rbac_authz = rbac_authz
    fastapi_app.state.oidc_validator = oidc_validator
    fastapi_app.state.operator_store = operator_store
    fastapi_app.state.bootstrapper = bootstrapper
    fastapi_app.state.readiness_checks = {
        "postgres": _check(),
        "openfga": _check(),
        "redis": _check(),
    }
    fastapi_app.state.metrics = FakeMetrics()

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_health_is_unauthenticated(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_livez_checks_no_dependencies(app, client):
    app.state.readiness_checks["postgres"] = _check(fails=True)
    assert client.get("/livez").status_code == 200


@pytest.mark.parametrize("path", ["/readyz", "/health"])
def test_ready_when_every_dependency_answers(client, path):
    resp = client.get(path)

    assert resp.status_code == 200
    assert resp.json() == {
        "status": "ok",
        "checks": {"postgres": "ok", "openfga": "ok", "redis": "ok"},
    }


@pytest.mark.parametrize("path", ["/readyz", "/health"])
@pytest.mark.parametrize("failing", ["postgres", "openfga", "redis"])
def test_any_failing_dependency_is_a_503(app, client, path, failing):
    """REL3-7: this used to be a 200 with "degraded" in the body (and
    Postgres/Redis weren't checked at all), so load balancers kept
    routing to an instance that couldn't serve."""
    app.state.readiness_checks[failing] = _check(fails=True)

    resp = client.get(path)

    assert resp.status_code == 503
    assert resp.json()["checks"][failing] == "unavailable"


def test_readiness_never_echoes_exception_text(app, client):
    """SEC3-11: `/health` is unauthenticated — it used to return
    `f"unreachable: {exc}"`, leaking internal URLs and messages."""
    app.state.readiness_checks["openfga"] = _check(fails=True)

    body = client.get("/readyz").text

    assert "10.0.0.7" not in body
    assert "secret detail" not in body


def test_a_hanging_dependency_is_bounded(app, client, monkeypatch):
    import time

    monkeypatch.setattr(health_routes, "CHECK_TIMEOUT_SECONDS", 0.05)
    app.state.readiness_checks["redis"] = _check(hangs=True)

    started = time.monotonic()
    resp = client.get("/readyz")

    assert resp.status_code == 503
    assert time.monotonic() - started < 2


def test_metrics_requires_system_auditor(client):
    resp = client.get("/api/v1/metrics", headers=bearer())
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_metrics_reports_counters_and_duration_summaries(client, app, rbac_authz):
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    app.state.metrics = FakeMetrics(
        counters={"authz.checks": 3}, durations={"authz.check": [1.0, 2.0, 3.0]}
    )

    resp = client.get("/api/v1/metrics", headers=bearer())

    assert resp.status_code == 200
    body = resp.json()
    assert body["counters"] == {"authz.checks": 3}
    assert body["durations"]["authz.check"] == {"count": 3, "sum": 6.0, "avg": 2.0}


@pytest.mark.asyncio
async def test_metrics_duration_summary_handles_no_observations(client, app, rbac_authz):
    """An empty ring buffer for a duration name must not raise a
    division-by-zero — `avg` reports 0.0 instead."""
    await rbac_authz.grant(Identity(id="user:alice"), "auditor", System(id=SYSTEM_OBJECT_ID))
    app.state.metrics = FakeMetrics(durations={"authz.check": []})

    resp = client.get("/api/v1/metrics", headers=bearer())

    assert resp.status_code == 200
    assert resp.json()["durations"]["authz.check"] == {"count": 0, "sum": 0, "avg": 0.0}

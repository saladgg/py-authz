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


class FakeProductFGAClient:
    def __init__(self, *, fails=False):
        self.fails = fails

    async def get_latest_model(self):
        if self.fails:
            raise ExternalServiceError("openfga is down")
        return {"id": "model-1"}


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
    fastapi_app.state.product_fga_client = FakeProductFGAClient()
    fastapi_app.state.metrics = FakeMetrics()

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app)


def test_health_is_unauthenticated(client):
    resp = client.get("/health")
    assert resp.status_code == 200


def test_health_reports_ok_when_openfga_is_reachable(client):
    resp = client.get("/health")
    assert resp.json() == {"status": "ok", "checks": {"openfga": "ok"}}


def test_health_reports_degraded_when_openfga_is_unreachable(app, client):
    app.state.product_fga_client = FakeProductFGAClient(fails=True)

    resp = client.get("/health")

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "degraded"
    assert body["checks"]["openfga"].startswith("unreachable:")


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

"""Tests for py_authz.control_plane.logging_middleware (CP-18)."""

import json
import logging

import pytest
from fastapi import FastAPI, Request
from starlette.testclient import TestClient

from py_authz.control_plane.auth import CurrentPrincipal
from py_authz.control_plane.logging_middleware import install_request_logging
from py_authz.core.types import Identity


@pytest.fixture
def app():
    fastapi_app = FastAPI()
    install_request_logging(fastapi_app)

    @fastapi_app.get("/ok")
    async def ok():
        return {"status": "ok"}

    @fastapi_app.get("/stamped")
    async def stamped(request: Request):
        request.state.principal = CurrentPrincipal(
            identity=Identity(id="user:alice"), kind="operator"
        )
        return {"status": "ok"}

    @fastapi_app.get("/boom")
    async def boom():
        raise RuntimeError("boom")

    return fastapi_app


@pytest.fixture
def client(app):
    return TestClient(app, raise_server_exceptions=False)


def _last_json_record(caplog):
    records = [r for r in caplog.records if r.name == "py_authz.control_plane.requests"]
    assert records, "expected at least one control-plane request log record"
    return json.loads(records[-1].message)


def test_logs_method_path_and_status(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/ok")

    payload = _last_json_record(caplog)
    assert payload["method"] == "GET"
    assert payload["path"] == "/ok"
    assert payload["status_code"] == 200
    assert isinstance(payload["duration_ms"], float)


def test_logs_no_principal_when_unauthenticated(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/ok")

    payload = _last_json_record(caplog)
    assert payload["principal"] is None
    assert payload["principal_kind"] is None


def test_logs_the_resolved_principal_when_present(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/stamped")

    payload = _last_json_record(caplog)
    assert payload["principal"] == "user:alice"
    assert payload["principal_kind"] == "operator"


def test_logs_at_error_level_on_5xx(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/boom")

    records = [r for r in caplog.records if r.name == "py_authz.control_plane.requests"]
    assert records[-1].levelno == logging.ERROR
    payload = json.loads(records[-1].message)
    assert payload["path"] == "/boom"


def test_never_logs_request_headers_or_body(client, caplog):
    """CP-17/CP-18: never a query string, header, or body — just
    method/path/status/duration/principal."""
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/ok", headers={"Authorization": "Bearer super-secret-value"})

    payload = _last_json_record(caplog)
    assert set(payload.keys()) == {
        "event",
        "request_id",
        "method",
        "path",
        "status_code",
        "duration_ms",
        "principal",
        "principal_kind",
    }
    assert "super-secret-value" not in json.dumps(payload)


# REL3-24: request ids in request logs and on the response.


def test_generates_a_request_id_and_returns_it(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        resp = client.get("/ok")

    payload = _last_json_record(caplog)
    assert payload["request_id"]
    assert resp.headers["X-Request-ID"] == payload["request_id"]


def test_reuses_a_safe_caller_request_id(client, caplog):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        resp = client.get("/ok", headers={"X-Request-ID": "panel-abc.123"})

    assert _last_json_record(caplog)["request_id"] == "panel-abc.123"
    assert resp.headers["X-Request-ID"] == "panel-abc.123"


@pytest.mark.parametrize("bad", ["has space", "x" * 129, 'quote"injection', ""])
def test_replaces_an_unsafe_caller_request_id(client, caplog, bad):
    with caplog.at_level(logging.INFO, logger="py_authz.control_plane.requests"):
        client.get("/ok", headers={"X-Request-ID": bad})

    request_id = _last_json_record(caplog)["request_id"]
    assert request_id != bad
    assert len(request_id) == 36  # a fresh uuid4


def test_records_request_count_errors_and_duration(app, client):
    """REL3-24: a control-plane request-duration metric."""
    from py_authz.core.metrics import Metrics

    app.state.metrics = Metrics()

    client.get("/ok")
    client.get("/boom")

    assert app.state.metrics.counters == {
        "control_plane_requests_total": 2,
        "control_plane_request_errors_total": 1,
    }
    assert len(app.state.metrics.durations["control_plane_request_duration_ms"]) == 2


def test_counts_a_5xx_response_as_an_error(app, client):
    from fastapi.responses import JSONResponse

    from py_authz.core.metrics import Metrics

    @app.get("/unavailable")
    async def unavailable():
        return JSONResponse({}, status_code=503)

    app.state.metrics = Metrics()
    client.get("/unavailable")

    assert app.state.metrics.counters["control_plane_request_errors_total"] == 1

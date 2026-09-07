"""Tests for py_authz.control_plane.errors (CP-1)."""

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from py_authz.control_plane.errors import authz_error_handler, status_code_for
from py_authz.core.exceptions import (
    AuthenticationError,
    AuthorizationDenied,
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    InvalidAuthzRequest,
    ModelValidationError,
    ServiceUnavailable,
    TenantNotFoundError,
)


def test_authentication_error_is_401():
    assert status_code_for(AuthenticationError("bad token")) == 401


def test_authorization_denied_is_403():
    assert status_code_for(AuthorizationDenied()) == 403


def test_tenant_not_found_is_404():
    assert status_code_for(TenantNotFoundError("no such tenant")) == 404


def test_invalid_authz_request_is_400():
    assert status_code_for(InvalidAuthzRequest("bad request")) == 400


def test_external_service_error_is_503():
    assert status_code_for(ExternalServiceError("openfga down")) == 503


def test_service_unavailable_subclass_is_still_503():
    """`ServiceUnavailable` inherits from `ExternalServiceError` — the
    most-specific-first ordering must not accidentally shadow it onto a
    different code."""
    assert status_code_for(ServiceUnavailable("down")) == 503


def test_configuration_error_is_500():
    assert status_code_for(ConfigurationError("bad config")) == 500


def test_model_validation_error_subclass_of_configuration_is_500():
    assert status_code_for(ModelValidationError("cycle detected")) == 500


def test_unknown_authz_error_subclass_falls_back_to_500():
    class SomeNewError(AuthzError):
        pass

    assert status_code_for(SomeNewError("whatever")) == 500


# -------------------------------------------------------------------
# authz_error_handler — the registered FastAPI exception handler that
# uses status_code_for(), converting every AuthzError into a JSON body
# instead of an unhandled-exception 500.
# -------------------------------------------------------------------


@pytest.fixture
def client():
    app = FastAPI()
    app.add_exception_handler(AuthzError, authz_error_handler)

    @app.get("/denied")
    async def denied():
        raise AuthorizationDenied("nope")

    @app.get("/misconfigured")
    async def misconfigured():
        raise ConfigurationError("bad config")

    return TestClient(app, raise_server_exceptions=False)


def test_client_error_is_reported_without_a_traceback_log(client, caplog):
    resp = client.get("/denied")

    assert resp.status_code == 403
    assert resp.json() == {"error": "AuthorizationDenied", "detail": "nope"}


def test_server_error_logs_a_traceback(client, caplog):
    """The >=500 branch logs at `exception` level (full traceback) —
    an operator-facing misconfiguration, unlike a routine 4xx denial,
    which is only logged at `info`."""
    with caplog.at_level("ERROR", logger="py_authz.control_plane"):
        resp = client.get("/misconfigured")

    assert resp.status_code == 500
    assert resp.json() == {"error": "ConfigurationError", "detail": "bad config"}
    assert any("control-plane request failed" in r.message for r in caplog.records)

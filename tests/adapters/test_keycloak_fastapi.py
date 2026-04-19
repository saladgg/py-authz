"""
Tests for the Keycloak FastAPI middleware.

The ``jwt`` module is stubbed in ``test_keycloak`` via sys.modules; importing
that module first ensures the fake is in place before keycloak_fastapi loads
the validator class.
"""

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from py_authz.adapters.keycloak import KeycloakJWTValidator  # noqa: E402
from py_authz.adapters.keycloak_fastapi import KeycloakAuthMiddleware  # noqa: E402
from py_authz.core.exceptions import AuthenticationError  # noqa: E402
from py_authz.core.types import Identity  # noqa: E402
from tests.adapters.test_keycloak import _install_fake_jwt  # noqa: F401


class StubValidator:
    def __init__(self, payload=None, error=None, identity=None):
        self._payload = payload or {"sub": "me"}
        self._error = error
        self._identity = identity or Identity(id="user:me")

    async def validate(self, token: str):
        if self._error:
            raise self._error
        return self._payload

    def to_identity(self, payload):
        return self._identity


def _build_app(validator):
    app = FastAPI()
    app.add_middleware(KeycloakAuthMiddleware, validator=validator)

    @app.get("/whoami")
    async def whoami(request: Request):
        user = getattr(request.state, "user", None)
        return {"user": user.id if user else None}

    return app


def test_middleware_noop_without_bearer():
    app = _build_app(StubValidator())
    client = TestClient(app)

    res = client.get("/whoami")

    assert res.status_code == 200
    assert res.json() == {"user": None}


def test_middleware_attaches_identity_on_valid_token():
    validator = StubValidator(identity=Identity(id="user:abc"))
    app = _build_app(validator)
    client = TestClient(app)

    res = client.get("/whoami", headers={"Authorization": "Bearer some-token"})

    assert res.status_code == 200
    assert res.json() == {"user": "user:abc"}


@pytest.mark.asyncio
async def test_middleware_raises_http_exception_on_invalid_token():
    from fastapi import HTTPException

    validator = StubValidator(error=AuthenticationError("nope"))
    middleware = KeycloakAuthMiddleware(app=lambda *a: None, validator=validator)

    class _Req:
        headers = {"Authorization": "Bearer bad-token"}

        class state:
            pass

    async def _call_next(_):
        raise AssertionError("call_next should not run on invalid token")

    with pytest.raises(HTTPException) as exc_info:
        await middleware.dispatch(_Req(), _call_next)

    assert exc_info.value.status_code == 401


@pytest.mark.asyncio
async def test_real_validator_class_still_instantiable():
    """Smoke test: confirms the sys.modules stub is compatible with imports."""
    v = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")
    assert v.audience == "aud"

"""
Unit tests for KeycloakJWTValidator.

The production module imports PyJWT at module level; when the library is not
installed we stub the subset of the API we need so the validator logic itself
is still exercised by coverage.
"""

import sys
import types
from typing import Any

import httpx
import pytest


class _FakeExpired(Exception):
    pass


class _FakeInvalid(Exception):
    pass


class _FakeAlgorithms:
    class RSAAlgorithm:
        @staticmethod
        def from_jwk(key):
            return f"public-key-for-{key['kid']}"


def _install_fake_jwt() -> types.ModuleType | None:
    """Inject a minimal fake ``jwt`` module if the real one is missing."""
    if "jwt" in sys.modules:
        return None

    fake = types.ModuleType("jwt")
    fake.ExpiredSignatureError = _FakeExpired
    fake.InvalidTokenError = _FakeInvalid
    fake.algorithms = _FakeAlgorithms
    fake.get_unverified_header = lambda token: {"kid": "k1"}
    fake.decode = lambda *a, **k: {"sub": "sub-123"}
    sys.modules["jwt"] = fake
    return fake


_install_fake_jwt()

import jwt  # noqa: E402

from py_authz.adapters.keycloak import KeycloakJWTValidator  # noqa: E402
from py_authz.core.exceptions import AuthenticationError  # noqa: E402


class FakeHTTPClient:
    def __init__(self, response_data: dict[str, Any], status_code: int = 200):
        self._response_data = response_data
        self._status_code = status_code
        self.calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url):
        self.calls.append(url)
        return _FakeResponse(self._response_data, self._status_code)


class _FakeResponse:
    def __init__(self, data, status_code):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=self)

    def json(self):
        return self._data


@pytest.fixture
def patch_async_client(monkeypatch):
    def _apply(http_client):
        def factory(*_a, **_kw):
            return http_client

        monkeypatch.setattr(httpx, "AsyncClient", factory)

    return _apply


@pytest.mark.asyncio
async def test_fetch_jwks_caches_result(patch_async_client):
    http = FakeHTTPClient({"keys": [{"kid": "k1"}]})
    patch_async_client(http)

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    jwks1 = await validator._get_jwks()
    jwks2 = await validator._get_jwks()

    assert jwks1 == {"keys": [{"kid": "k1"}]}
    assert jwks2 is jwks1
    assert http.calls == ["https://kc/realms/r/protocol/openid-connect/certs"]


def test_to_identity_returns_prefixed_id():
    validator = KeycloakJWTValidator(issuer="https://kc/realms/r/", audience="aud")

    identity = validator.to_identity({"sub": "abc"})

    assert identity.id == "user:abc"
    # trailing slash is stripped in constructor
    assert validator.issuer == "https://kc/realms/r"


def test_to_identity_raises_when_sub_missing():
    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="Missing 'sub'"):
        validator.to_identity({})


@pytest.mark.asyncio
async def test_validate_returns_payload(monkeypatch, patch_async_client):
    patch_async_client(FakeHTTPClient({"keys": [{"kid": "k1"}]}))

    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})
    monkeypatch.setattr(jwt, "decode", lambda *a, **k: {"sub": "me"})

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    payload = await validator.validate("some-token")

    assert payload == {"sub": "me"}


@pytest.mark.asyncio
async def test_validate_raises_when_kid_unknown(monkeypatch, patch_async_client):
    patch_async_client(FakeHTTPClient({"keys": [{"kid": "other"}]}))
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "missing"})

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")


@pytest.mark.asyncio
async def test_validate_raises_on_expired_signature(monkeypatch, patch_async_client):
    patch_async_client(FakeHTTPClient({"keys": [{"kid": "k1"}]}))
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})

    def _expired(*_a, **_kw):
        raise jwt.ExpiredSignatureError("expired")

    monkeypatch.setattr(jwt, "decode", _expired)

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="expired"):
        await validator.validate("some-token")


@pytest.mark.asyncio
async def test_validate_raises_on_invalid_token(monkeypatch, patch_async_client):
    patch_async_client(FakeHTTPClient({"keys": [{"kid": "k1"}]}))
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})

    def _invalid(*_a, **_kw):
        raise jwt.InvalidTokenError("bad")

    monkeypatch.setattr(jwt, "decode", _invalid)

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="Invalid token"):
        await validator.validate("some-token")

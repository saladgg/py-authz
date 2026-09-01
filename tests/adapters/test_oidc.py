"""
Unit tests for OIDCJWTValidator — the generic base `KeycloakJWTValidator`
now subclasses.

Reuses the fake-`jwt`-module bootstrap from `test_keycloak` so this runs
correctly whether or not PyJWT is actually installed.
"""

from typing import Any

import httpx
import pytest

from tests.adapters.test_keycloak import _install_fake_jwt  # noqa: F401 — side effect

_install_fake_jwt()

import jwt  # noqa: E402

from py_authz.adapters.oidc import OIDCJWTValidator  # noqa: E402
from py_authz.core.exceptions import AuthenticationError  # noqa: E402


class _FakeResponse:
    def __init__(self, data, status_code=200):
        self._data = data
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("err", request=None, response=self)

    def json(self):
        return self._data


class RoutedHTTPClient:
    """Fake `httpx.AsyncClient` that returns a canned response per URL,
    recording every call made."""

    def __init__(self, responses: dict[str, Any]):
        self._responses = responses
        self.calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url):
        self.calls.append(url)
        return _FakeResponse(self._responses[url])


@pytest.fixture
def patch_async_client(monkeypatch):
    def _apply(http_client):
        def factory(*_a, **_kw):
            return http_client

        monkeypatch.setattr(httpx, "AsyncClient", factory)

    return _apply


@pytest.mark.asyncio
async def test_resolves_jwks_url_via_discovery_when_not_explicit(patch_async_client):
    """
    Regression test for SEC-2: with no explicit `jwks_url`, the JWKS
    endpoint is resolved from the provider's OIDC discovery document —
    generic, non-Keycloak-specific behavior that `KeycloakJWTValidator`
    deliberately opts out of (it always passes `jwks_url` explicitly).
    """
    http = RoutedHTTPClient(
        {
            "https://auth.example.com/.well-known/openid-configuration": {
                "jwks_uri": "https://auth.example.com/oauth2/v1/keys",
            },
            "https://auth.example.com/oauth2/v1/keys": {"keys": [{"kid": "k1"}]},
        }
    )
    patch_async_client(http)

    validator = OIDCJWTValidator(issuer="https://auth.example.com", audience="aud")

    jwks = await validator._get_jwks()

    assert jwks == {"keys": [{"kid": "k1"}]}
    assert http.calls == [
        "https://auth.example.com/.well-known/openid-configuration",
        "https://auth.example.com/oauth2/v1/keys",
    ]


@pytest.mark.asyncio
async def test_discovery_document_is_cached_across_calls(patch_async_client):
    http = RoutedHTTPClient(
        {
            "https://auth.example.com/.well-known/openid-configuration": {
                "jwks_uri": "https://auth.example.com/oauth2/v1/keys",
            },
            "https://auth.example.com/oauth2/v1/keys": {"keys": [{"kid": "k1"}]},
        }
    )
    patch_async_client(http)

    validator = OIDCJWTValidator(issuer="https://auth.example.com", audience="aud")

    await validator._resolve_jwks_url()
    await validator._resolve_jwks_url()

    # Only one discovery-document fetch across two resolutions.
    assert http.calls.count("https://auth.example.com/.well-known/openid-configuration") == 1


@pytest.mark.asyncio
async def test_explicit_jwks_url_skips_discovery(patch_async_client):
    http = RoutedHTTPClient({"https://auth.example.com/keys": {"keys": [{"kid": "k1"}]}})
    patch_async_client(http)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )

    jwks = await validator._get_jwks()

    assert jwks == {"keys": [{"kid": "k1"}]}
    # No discovery-document call at all.
    assert http.calls == ["https://auth.example.com/keys"]


@pytest.mark.asyncio
async def test_validate_raises_clear_message_on_audience_mismatch(monkeypatch, patch_async_client):
    """Regression test for SEC-2: an audience mismatch gets a specific,
    actionable message — not a generic "Invalid token: ..."."""
    patch_async_client(
        RoutedHTTPClient(
            {
                "https://auth.example.com/keys": {"keys": [{"kid": "k1"}]},
            }
        )
    )
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})

    def _raise_invalid_audience(*_a, **_kw):
        raise jwt.InvalidAudienceError("aud mismatch")

    monkeypatch.setattr(jwt, "decode", _raise_invalid_audience)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="expected-aud",
        jwks_url="https://auth.example.com/keys",
    )

    with pytest.raises(AuthenticationError, match="audience mismatch"):
        await validator.validate("some-token")

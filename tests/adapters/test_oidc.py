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
from py_authz.core.exceptions import (  # noqa: E402
    AuthenticationError,
    IdentityProviderUnavailable,
)


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


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-7: the IdP itself being unreachable
# (network error / timeout / non-2xx) used to propagate as a raw httpx
# exception, crashing every authenticated request with an unhandled 500
# for as long as the outage lasted.
# ----------------------------------------------------------------------


class FailingHTTPClient:
    """Fake `httpx.AsyncClient` whose every `get()` raises."""

    def __init__(self, exc: Exception):
        self._exc = exc

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url):
        raise self._exc


@pytest.mark.asyncio
async def test_discovery_failure_raises_identity_provider_unavailable(patch_async_client):
    patch_async_client(FailingHTTPClient(httpx.ConnectError("boom")))

    validator = OIDCJWTValidator(issuer="https://auth.example.com", audience="aud")

    with pytest.raises(IdentityProviderUnavailable):
        await validator._resolve_jwks_url()


@pytest.mark.asyncio
async def test_jwks_fetch_failure_raises_identity_provider_unavailable(patch_async_client):
    patch_async_client(FailingHTTPClient(httpx.TimeoutException("boom")))

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )

    with pytest.raises(IdentityProviderUnavailable):
        await validator._fetch_jwks()


@pytest.mark.asyncio
async def test_jwks_fetch_http_status_error_raises_identity_provider_unavailable(
    patch_async_client,
):
    class ErroringResponseClient:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_):
            return False

        async def get(self, url):
            return _FakeResponse({}, status_code=503)

    patch_async_client(ErroringResponseClient())

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )

    with pytest.raises(IdentityProviderUnavailable):
        await validator._fetch_jwks()


# ----------------------------------------------------------------------
# Regression coverage for SEC2-2: `to_identity()` now carries the full
# decoded token payload as `Identity.attributes`, so a caller can build a
# tenant resolver off a verified claim instead of a raw request header.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_validate_raises_clean_error_when_kid_missing(monkeypatch, patch_async_client):
    """
    Regression test for DX2-5: a token with no `kid` header (valid per
    spec, or trivially crafted) used to raise a bare, uncaught `KeyError`
    instead of `AuthenticationError`.
    """
    patch_async_client(
        RoutedHTTPClient({"https://auth.example.com/keys": {"keys": [{"kid": "k1"}]}})
    )
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"alg": "RS256"})  # no "kid"

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )

    with pytest.raises(AuthenticationError, match="missing kid"):
        await validator.validate("some-token")


def test_to_identity_carries_full_payload_as_attributes():
    validator = OIDCJWTValidator(issuer="https://auth.example.com", audience="aud")

    identity = validator.to_identity({"sub": "abc", "tenant_id": "acme"})

    assert identity.id == "user:abc"
    assert identity.attributes == {"sub": "abc", "tenant_id": "acme"}

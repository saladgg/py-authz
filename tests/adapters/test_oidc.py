"""
Unit tests for OIDCJWTValidator — the generic base `KeycloakJWTValidator`
now subclasses.

Reuses the fake-`jwt`-module bootstrap from `test_keycloak` so this runs
correctly whether or not PyJWT is actually installed.
"""

import asyncio
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


@pytest.fixture(autouse=True)
def _stub_jwk_parsing(monkeypatch):
    """Every test here mocks `jwt.decode` and feeds placeholder JWKs
    (`{"kid": "k1"}`), so key parsing is stubbed too. Real signature
    verification is covered by tests/adapters/test_oidc_signed_tokens.py.
    (This used to work only because test_keycloak.py could replace PyJWT
    with a fake for the whole session — see `_install_fake_jwt`.)"""
    monkeypatch.setattr(
        jwt.algorithms.RSAAlgorithm, "from_jwk", staticmethod(lambda key: "placeholder-key")
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


# ----------------------------------------------------------------------
# Regression coverage for DX2-9: an optional `leeway` constructor
# parameter, threaded through to `jwt.decode`, tolerating clock skew
# between this service and the IdP.
# ----------------------------------------------------------------------


def _install_leeway_aware_fake_decode(monkeypatch, *, expired_by: float):
    """
    Monkeypatch `jwt.decode` to mimic real PyJWT's `exp`/`leeway`
    semantics for a token that expired `expired_by` seconds ago —
    without depending on whether the real, cryptography-backed PyJWT or
    this test module's own fake stub (`test_keycloak._install_fake_jwt`)
    happens to be the one installed under `sys.modules["jwt"]` in this
    session (collection order-dependent). This is the same
    monkeypatched-`jwt.decode` pattern
    `test_validate_raises_clear_message_on_audience_mismatch` above
    already uses; it exercises exactly the thing DX2-9 changed —
    `OIDCJWTValidator.validate()` must actually forward its `leeway` to
    `jwt.decode(..., leeway=...)` — without re-testing PyJWT's own
    already-well-tested `exp` arithmetic.
    """

    def fake_decode(token, key, *, leeway=0, **kwargs):
        if expired_by > leeway:
            raise jwt.ExpiredSignatureError("Signature has expired")
        return {"sub": "alice"}

    monkeypatch.setattr(jwt, "decode", fake_decode)


@pytest.mark.asyncio
async def test_token_just_outside_default_leeway_rejected_with_leeway_zero(
    monkeypatch, patch_async_client
):
    patch_async_client(
        RoutedHTTPClient({"https://auth.example.com/keys": {"keys": [{"kid": "k1"}]}})
    )
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})
    _install_leeway_aware_fake_decode(monkeypatch, expired_by=30)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
        leeway=0,  # the default — explicit here for clarity
    )

    with pytest.raises(AuthenticationError, match="expired"):
        await validator.validate("some-token")


@pytest.mark.asyncio
async def test_token_just_outside_default_leeway_accepted_with_generous_leeway(
    monkeypatch, patch_async_client
):
    """A token that expired 30s ago is rejected with the default
    `leeway=0` (see the sibling test above) but accepted once `leeway` is
    set generously enough to cover that drift — confirming
    `OIDCJWTValidator.__init__`'s `leeway` param actually reaches
    `jwt.decode`."""
    patch_async_client(
        RoutedHTTPClient({"https://auth.example.com/keys": {"keys": [{"kid": "k1"}]}})
    )
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})
    _install_leeway_aware_fake_decode(monkeypatch, expired_by=30)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
        leeway=60,
    )

    payload = await validator.validate("some-token")
    assert payload["sub"] == "alice"


# ----------------------------------------------------------------------
# Regression coverage for the thundering-herd fix on `_get_jwks()`:
# concurrent callers during a cache-miss (cold start, or right after a
# key rotation invalidates the cache) must not each fire their own fetch
# against the IdP.
# ----------------------------------------------------------------------


class _SlowCountingHTTPClient:
    """Fake `httpx.AsyncClient` whose `get()` yields control (simulating
    real network latency) before responding, so concurrently-scheduled
    callers actually get a chance to race — and counts how many times it
    was actually called."""

    def __init__(self, data: dict[str, Any]):
        self._data = data
        self.call_count = 0

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url):
        self.call_count += 1
        await asyncio.sleep(0.01)
        return _FakeResponse(self._data)


@pytest.mark.asyncio
async def test_concurrent_cold_start_calls_only_fetch_jwks_once(patch_async_client):
    http = _SlowCountingHTTPClient({"keys": [{"kid": "k1"}]})
    patch_async_client(http)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )

    results = await asyncio.gather(*(validator._get_jwks() for _ in range(10)))

    assert http.call_count == 1
    assert all(r == {"keys": [{"kid": "k1"}]} for r in results)


@pytest.mark.asyncio
async def test_concurrent_force_refresh_calls_only_fetch_jwks_once(patch_async_client):
    """Same thundering-herd guard, but for the post-key-rotation forced
    refresh path (multiple concurrent callers hitting an unrecognized
    `kid` at once)."""
    http = _SlowCountingHTTPClient({"keys": [{"kid": "k2"}]})
    patch_async_client(http)

    validator = OIDCJWTValidator(
        issuer="https://auth.example.com",
        audience="aud",
        jwks_url="https://auth.example.com/keys",
    )
    # Prime the cache so `force_refresh=True` below exercises the
    # refresh path, not the cold-start path already covered above.
    await validator._get_jwks()
    assert http.call_count == 1

    results = await asyncio.gather(*(validator._get_jwks(force_refresh=True) for _ in range(10)))

    # One caller performs the actual forced refetch; the rest, having
    # waited on the lock, see the cooldown already consumed and reuse
    # its result instead of each refetching.
    assert http.call_count == 2
    assert all(r == {"keys": [{"kid": "k2"}]} for r in results)

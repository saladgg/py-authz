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


class _FakeInvalidAudience(_FakeInvalid):
    pass


class _FakeAlgorithms:
    class RSAAlgorithm:
        @staticmethod
        def from_jwk(key):
            return f"public-key-for-{key['kid']}"


def _install_fake_jwt() -> types.ModuleType | None:
    """Inject a minimal fake ``jwt`` module if the real one is missing.

    "Missing" means *not installed*, not "not imported yet": this used to
    check only `sys.modules`, so whenever this file happened to be
    collected before anything imported PyJWT, the fake replaced the real
    library for the whole test session — silently breaking every later
    test that needs real signatures (e.g. test_oidc_signed_tokens.py).
    """
    if "jwt" in sys.modules:
        return None
    try:
        import jwt as _real_jwt  # noqa: F401
    except ImportError:
        pass
    else:
        return None

    fake = types.ModuleType("jwt")
    fake.ExpiredSignatureError = _FakeExpired
    fake.InvalidTokenError = _FakeInvalid
    fake.InvalidAudienceError = _FakeInvalidAudience
    fake.algorithms = _FakeAlgorithms
    fake.get_unverified_header = lambda token: {"kid": "k1"}
    fake.decode = lambda *a, **k: {"sub": "sub-123"}
    sys.modules["jwt"] = fake
    return fake


_install_fake_jwt()

import jwt  # noqa: E402

from py_authz.adapters.keycloak import KeycloakJWTValidator  # noqa: E402
from py_authz.core.exceptions import AuthenticationError  # noqa: E402


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


class SequencedHTTPClient:
    """Returns a different JSON body on each successive `.get()` call,
    holding on the last one once the sequence is exhausted."""

    def __init__(self, responses: list[dict], status_code: int = 200):
        self._responses = list(responses)
        self._status_code = status_code
        self.calls: list[str] = []

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_):
        return False

    async def get(self, url):
        self.calls.append(url)
        index = min(len(self.calls) - 1, len(self._responses) - 1)
        return _FakeResponse(self._responses[index], self._status_code)


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


def test_jwks_url_is_deterministic_and_public():
    """
    Regression test for SEC-2: `KeycloakJWTValidator` always passes an
    explicit `jwks_url` to the `OIDCJWTValidator` base — it must never
    attempt OIDC discovery (Keycloak's JWKS path is deterministic).
    `jwks_url` is preserved as a plain public attribute for backward
    compatibility with code written before the `OIDCJWTValidator` split.
    """
    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    assert validator.jwks_url == "https://kc/realms/r/protocol/openid-connect/certs"
    assert validator._explicit_jwks_url == validator.jwks_url


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
async def test_validate_raises_keycloak_specific_message_on_audience_mismatch(
    monkeypatch, patch_async_client
):
    """
    Regression test for SEC-2: Keycloak's audience-mismatch message names
    the specific, well-known gotcha (access tokens default to
    `aud: "account"` unless an audience mapper is added) — not just the
    generic `OIDCJWTValidator` wording.
    """
    patch_async_client(FakeHTTPClient({"keys": [{"kid": "k1"}]}))
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "k1"})

    def _raise_invalid_audience(*_a, **_kw):
        raise jwt.InvalidAudienceError("aud mismatch")

    monkeypatch.setattr(jwt, "decode", _raise_invalid_audience)

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="audience mapper"):
        await validator.validate("some-token")


@pytest.mark.asyncio
async def test_validate_raises_when_kid_unknown(monkeypatch, patch_async_client):
    http = SequencedHTTPClient([{"keys": [{"kid": "other"}]}])
    patch_async_client(http)
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "missing"})

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")

    # Regression guard for SEC-1: a still-unknown kid must trigger exactly
    # one forced refetch attempt (base fetch + one refresh) before giving
    # up, not zero (the old behavior) and not unbounded retries.
    assert len(http.calls) == 2


@pytest.mark.asyncio
async def test_validate_refetches_jwks_once_when_kid_rotated(monkeypatch, patch_async_client):
    """
    Regression test for SEC-1: Keycloak rotates its signing keys (a
    routine operational event) — a token signed with the new key must
    validate without a process restart, via exactly one forced JWKS
    refetch.
    """
    http = SequencedHTTPClient(
        [
            {"keys": [{"kid": "old"}]},
            {"keys": [{"kid": "new"}]},
        ]
    )
    patch_async_client(http)

    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "new"})
    monkeypatch.setattr(jwt, "decode", lambda *a, **k: {"sub": "me"})

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    payload = await validator.validate("some-token")

    assert payload == {"sub": "me"}
    assert len(http.calls) == 2  # initial fetch (miss) + forced refetch (hit)


@pytest.mark.asyncio
async def test_validate_rate_limits_forced_refetch_within_cooldown(monkeypatch, patch_async_client):
    """
    Regression test for SEC-1: a client repeatedly sending an unknown
    `kid` must not be able to force unlimited JWKS refetches — the second
    `validate()` call here lands well inside the default 60s cooldown, so
    it must not trigger another HTTP call.
    """
    http = SequencedHTTPClient([{"keys": [{"kid": "other"}]}])
    patch_async_client(http)
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "missing"})

    validator = KeycloakJWTValidator(issuer="https://kc/realms/r", audience="aud")

    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")
    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")

    assert len(http.calls) == 2


@pytest.mark.asyncio
async def test_validate_forced_refetch_allowed_again_after_cooldown(
    monkeypatch, patch_async_client
):
    """Once the cooldown elapses, a still-unknown kid may trigger another
    forced refetch."""
    http = SequencedHTTPClient([{"keys": [{"kid": "other"}]}])
    patch_async_client(http)
    monkeypatch.setattr(jwt, "get_unverified_header", lambda t: {"kid": "missing"})

    validator = KeycloakJWTValidator(
        issuer="https://kc/realms/r", audience="aud", jwks_refresh_cooldown=0.0
    )

    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")
    with pytest.raises(AuthenticationError, match="unknown kid"):
        await validator.validate("some-token")

    # Cooldown is 0 — every validate() call gets its own forced refetch:
    # base fetch + refetch (call 1) + refetch (call 2) = 3.
    assert len(http.calls) == 3


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

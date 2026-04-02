import time

import jwt as pyjwt
import pytest
from unittest.mock import MagicMock, patch

from django_authz.authentication.jwt import JWTAuthenticationBackend
from django_authz.conf import Settings


@pytest.mark.django_db
def test_decode_unverified_token():
    """JWTAuthenticationBackend.decode should decode a token when VERIFY_JWT=False."""
    secret = "mysecret"
    payload = {"sub": "user123", "email": "user@example.com"}
    token = pyjwt.encode(payload, secret, algorithm="HS256")

    backend = JWTAuthenticationBackend()
    decoded = backend.decode(token)
    assert decoded["sub"] == "user123"


@pytest.mark.django_db
def test_authenticate_returns_none_without_token(rf):
    """authenticate() returns None when no Bearer token is present."""
    backend = JWTAuthenticationBackend()
    request = rf.get("/")
    assert backend.authenticate(request) is None


@pytest.mark.django_db
def test_authenticate_with_valid_token(rf):
    """authenticate() returns a user and sets request.jwt_principal."""
    secret = "mysecret"
    payload = {"sub": "u1", "preferred_username": "alice", "email": "alice@example.com"}
    token = pyjwt.encode(payload, secret, algorithm="HS256")

    request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    backend = JWTAuthenticationBackend()
    user = backend.authenticate(request)

    assert user is not None
    assert user.username == "alice"
    assert request.jwt_principal.subject == "u1"


@pytest.mark.django_db
def test_authenticate_returns_none_for_invalid_token(rf):
    """authenticate() returns None when the token cannot be decoded."""
    request = rf.get("/", HTTP_AUTHORIZATION="Bearer notavalidtoken")
    backend = JWTAuthenticationBackend()
    assert backend.authenticate(request) is None


@pytest.mark.django_db
def test_authenticate_returns_none_when_sub_missing(rf):
    """authenticate() returns None when the JWT payload has no 'sub' claim."""
    secret = "mysecret"
    payload = {"email": "nosub@example.com"}
    token = pyjwt.encode(payload, secret, algorithm="HS256")
    request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    backend = JWTAuthenticationBackend()
    assert backend.authenticate(request) is None


def test_authenticate_returns_none_for_none_request():
    backend = JWTAuthenticationBackend()
    assert backend.authenticate(None) is None


@pytest.mark.django_db
def test_authenticate_falls_back_to_email_as_username(rf):
    """authenticate() uses email as username when preferred_username is absent."""
    secret = "mysecret"
    payload = {"sub": "u2", "email": "bob@example.com"}
    token = pyjwt.encode(payload, secret, algorithm="HS256")
    request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    backend = JWTAuthenticationBackend()
    user = backend.authenticate(request)
    assert user.username == "bob@example.com"


@pytest.mark.django_db
def test_authenticate_falls_back_to_sub_as_username(rf):
    """authenticate() uses sub as username when preferred_username and email are absent."""
    secret = "mysecret"
    payload = {"sub": "raw-sub-id"}
    token = pyjwt.encode(payload, secret, algorithm="HS256")
    request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")
    backend = JWTAuthenticationBackend()
    user = backend.authenticate(request)
    assert user.username == "raw-sub-id"


def test_infer_jwks_url_with_keycloak_config():
    with patch("django_authz.authentication.jwt.CONFIG") as mock_config:
        mock_config.KEYCLOAK_URL = "https://auth.example.com"
        mock_config.KEYCLOAK_REALM = "myrealm"
        url = JWTAuthenticationBackend._infer_jwks_url()
    assert url == "https://auth.example.com/realms/myrealm/protocol/openid-connect/certs"


def test_infer_jwks_url_returns_none_without_config():
    with patch("django_authz.authentication.jwt.CONFIG") as mock_config:
        mock_config.KEYCLOAK_URL = None
        mock_config.KEYCLOAK_REALM = None
        url = JWTAuthenticationBackend._infer_jwks_url()
    assert url is None


# ---------------------------------------------------------------------------
# VERIFY_JWT=True path — signature verification with RSA key
# ---------------------------------------------------------------------------


def test_decode_verified_rsa_token(rsa_key_pair):
    """decode() verifies an RS256 token when VERIFY_JWT=True by delegating to the JWKS client."""
    private_key, public_key = rsa_key_pair
    now = int(time.time())
    payload = {
        "sub": "verified-user",
        "email": "v@example.com",
        "iat": now,
        "exp": now + 3600,
    }
    token = pyjwt.encode(payload, private_key, algorithm="RS256")

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    mock_jwks_client = MagicMock()
    mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

    verified_config = Settings(VERIFY_JWT=True, JWKS_URL="https://example.com/jwks")
    backend = JWTAuthenticationBackend()
    backend._jwks_client = None  # reset any cached client from previous tests

    with (
        patch("django_authz.authentication.jwt.CONFIG", verified_config),
        patch.object(backend, "_get_jwks_client", return_value=mock_jwks_client),
    ):
        decoded = backend.decode(token)

    assert decoded["sub"] == "verified-user"
    mock_jwks_client.get_signing_key_from_jwt.assert_called_once_with(token)


@pytest.mark.django_db
def test_authenticate_with_verified_rsa_token(rf, rsa_key_pair):
    """authenticate() provisions a user when VERIFY_JWT=True and the token is valid."""
    private_key, public_key = rsa_key_pair
    now = int(time.time())
    payload = {
        "sub": "rsa-sub",
        "preferred_username": "rsauser",
        "email": "rsa@example.com",
        "iat": now,
        "exp": now + 3600,
    }
    token = pyjwt.encode(payload, private_key, algorithm="RS256")
    request = rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    mock_signing_key = MagicMock()
    mock_signing_key.key = public_key
    mock_jwks_client = MagicMock()
    mock_jwks_client.get_signing_key_from_jwt.return_value = mock_signing_key

    verified_config = Settings(VERIFY_JWT=True, JWKS_URL="https://example.com/jwks")
    backend = JWTAuthenticationBackend()
    backend._jwks_client = None

    with (
        patch("django_authz.authentication.jwt.CONFIG", verified_config),
        patch.object(backend, "_get_jwks_client", return_value=mock_jwks_client),
    ):
        user = backend.authenticate(request)

    assert user is not None
    assert user.username == "rsauser"
    assert request.jwt_principal.subject == "rsa-sub"


def test_get_jwks_client_raises_when_no_url_configured():
    """_get_jwks_client() raises ConfigurationError when JWKS_URL cannot be determined."""
    from django_authz.exceptions import ConfigurationError

    no_jwks_config = Settings(VERIFY_JWT=True)
    backend = JWTAuthenticationBackend()
    backend._jwks_client = None

    with (
        patch("django_authz.authentication.jwt.CONFIG", no_jwks_config),
        pytest.raises(ConfigurationError, match="JWKS URL"),
    ):
        backend._get_jwks_client()


def test_get_jwks_client_caches_instance():
    """_get_jwks_client() returns the same PyJWKClient instance on repeated calls."""
    from jwt import PyJWKClient

    cfg = Settings(VERIFY_JWT=True, JWKS_URL="https://example.com/jwks")
    backend = JWTAuthenticationBackend()
    backend._jwks_client = None

    with (
        patch("django_authz.authentication.jwt.CONFIG", cfg),
        patch("django_authz.authentication.jwt.PyJWKClient") as mock_cls,
    ):
        mock_cls.return_value = MagicMock(spec=PyJWKClient)
        first = backend._get_jwks_client()
        second = backend._get_jwks_client()

    assert first is second
    mock_cls.assert_called_once()  # constructed only once

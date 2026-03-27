import pytest
import jwt as pyjwt
from django_authz.authentication.jwt import JWTAuthenticationBackend


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

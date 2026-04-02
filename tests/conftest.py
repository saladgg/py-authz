"""Shared pytest fixtures for the django-authz test suite.

Provides factories and mocks used across multiple test modules, grouped by
concern:

Authentication
--------------
- ``faker``           – Faker instance for deterministic test data generation.
- ``jwt_payload``     – Realistic JWT claims dict built with Faker.
- ``make_jwt_token``  – Factory: sign any payload as HS256 (VERIFY_JWT=False mode).
- ``bearer_request``  – RequestFactory GET request pre-loaded with a Bearer token.
- ``rsa_key_pair``    – (private_key, public_key) RSA-2048 pair for RS256/VERIFY_JWT tests.

OpenFGA REST
------------
- ``mock_openfga_http`` – Patches ``requests.post``/``requests.get`` in the openfga
  module; yields a control handle so tests can configure ``allowed`` and
  ``relations`` per-test.

Keycloak
--------
- ``keycloak_config`` – Patches ``CONFIG`` with minimal Keycloak settings so
  ``get_openid()`` / ``KeycloakAdmin()`` don't raise on missing config.

Users
-----
- ``make_user`` – Django User factory powered by Faker; accepts keyword overrides.
"""

import time

import pytest
from faker import Faker

_faker = Faker()


# ---------------------------------------------------------------------------
# General purpose
# ---------------------------------------------------------------------------


@pytest.fixture
def rf():
    """Django RequestFactory for building fake HTTP requests."""
    from django.test import RequestFactory

    return RequestFactory()


@pytest.fixture
def faker() -> Faker:
    """Return a module-level Faker instance for test data generation."""
    return _faker


# ---------------------------------------------------------------------------
# User factory
# ---------------------------------------------------------------------------


@pytest.fixture
def make_user(db):
    """Factory fixture: create a Django User with Faker-generated defaults.

    Usage::

        def test_something(make_user):
            user = make_user()               # fully random
            admin = make_user(is_staff=True) # with overrides
    """
    from django.contrib.auth import get_user_model

    User = get_user_model()

    def _make(username: str | None = None, email: str | None = None, **kwargs):  # noqa: ANN003
        return User.objects.create_user(
            username=username or _faker.unique.user_name(),
            email=email or _faker.unique.email(),
            **kwargs,
        )

    return _make


# ---------------------------------------------------------------------------
# JWT helpers
# ---------------------------------------------------------------------------


@pytest.fixture
def jwt_payload() -> dict:
    """Return a realistic JWT payload dict with Faker-generated identity claims.

    Includes the three claims required when VERIFY_JWT=True (``sub``, ``iat``,
    ``exp``) plus ``preferred_username`` and ``email``.
    """
    now = int(time.time())
    return {
        "sub": str(_faker.uuid4()),
        "preferred_username": _faker.unique.user_name(),
        "email": _faker.unique.email(),
        "iat": now,
        "exp": now + 3600,
    }


@pytest.fixture
def make_jwt_token(jwt_payload):
    """Factory: sign a payload with HS256 (suitable when VERIFY_JWT=False).

    Usage::

        def test_something(make_jwt_token, jwt_payload):
            token = make_jwt_token()                       # uses default jwt_payload
            token = make_jwt_token({"sub": "x", ...})     # custom payload
    """
    import jwt as pyjwt

    def _make(payload: dict | None = None, secret: str = "test-secret") -> str:
        return pyjwt.encode(payload or jwt_payload, secret, algorithm="HS256")

    return _make


@pytest.fixture
def bearer_request(rf, make_jwt_token):
    """Return a GET request carrying a Bearer token.

    Usage::

        def test_something(bearer_request):
            request = bearer_request()              # token from default jwt_payload
            request = bearer_request({"sub": "x"}) # token from custom payload
    """

    def _make(payload: dict | None = None) -> object:
        token = make_jwt_token(payload)
        return rf.get("/", HTTP_AUTHORIZATION=f"Bearer {token}")

    return _make


# ---------------------------------------------------------------------------
# RSA key pair (for VERIFY_JWT=True tests)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def rsa_key_pair():
    """Generate a 2048-bit RSA key pair (session-scoped for speed).

    Returns a ``(private_key, public_key)`` tuple using the ``cryptography``
    package (installed transitively via PyJWT's RSA support).

    Usage::

        def test_verified(rsa_key_pair):
            private_key, public_key = rsa_key_pair
            token = jwt.encode(payload, private_key, algorithm="RS256")
    """
    from cryptography.hazmat.primitives.asymmetric import rsa

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


# ---------------------------------------------------------------------------
# OpenFGA REST mock
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_openfga_http():
    """Patch ``requests.post`` / ``requests.get`` in the OpenFGA REST client.

    Yields a control dict with keys:

    - ``"allowed"``   (bool, default True)  – returned by ``/check`` responses.
    - ``"relations"`` (list, default [])    – returned by ``/list-relations``.
    - ``"post"``      – the ``MagicMock`` for ``requests.post``.
    - ``"get"``       – the ``MagicMock`` for ``requests.get``.

    Usage::

        def test_denied(mock_openfga_http):
            mock_openfga_http["allowed"] = False
            client = OpenFGAClient(api_url="http://fga", store_id="s1")
            assert client.check("user:alice", "editor", "doc:1") is False
    """
    from unittest.mock import MagicMock, patch

    ctrl: dict = {"allowed": True, "relations": []}

    def _post(url, **_kwargs):
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        if "/check" in url:
            resp.json.return_value = {"allowed": ctrl["allowed"]}
        else:
            resp.json.return_value = {}
        return resp

    def _get(_url, **_kwargs):
        resp = MagicMock()
        resp.raise_for_status = lambda: None
        resp.json.return_value = {"relations": ctrl["relations"]}
        return resp

    with (
        patch("django_authz.authorization.openfga.requests.post", side_effect=_post) as mock_post,
        patch("django_authz.authorization.openfga.requests.get", side_effect=_get) as mock_get,
    ):
        ctrl["post"] = mock_post
        ctrl["get"] = mock_get
        yield ctrl


# ---------------------------------------------------------------------------
# Keycloak config
# ---------------------------------------------------------------------------


@pytest.fixture
def keycloak_config():
    """Patch CONFIG with minimal Keycloak settings.

    Necessary for any test that instantiates ``get_openid()`` or
    ``KeycloakAdmin()`` because both guard-check ``KEYCLOAK_URL`` and
    ``KEYCLOAK_REALM``.

    Usage::

        def test_admin(keycloak_config):
            admin = KeycloakAdmin()  # no longer raises RuntimeError
    """
    from unittest.mock import patch

    from django_authz.conf import Settings

    cfg = Settings(
        KEYCLOAK_URL="https://keycloak.example.com",
        KEYCLOAK_REALM="test-realm",
        KEYCLOAK_CLIENT_ID="backend",
        KEYCLOAK_CLIENT_SECRET="secret",
        VERIFY_JWT=False,
    )
    with patch("django_authz.authentication.keycloak.CONFIG", cfg):
        yield cfg

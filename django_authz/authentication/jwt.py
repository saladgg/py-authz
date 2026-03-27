"""
JWT Authentication backend for Django with optional signature verification via JWKS.

- By default, signature verification is **enabled** (VERIFY_JWT=True).
- JWKS URL is inferred from Keycloak settings if not explicitly provided.
- Audience and Issuer checks are optional but recommended.

Register in settings:
    AUTHENTICATION_BACKENDS = [
        "django_authz.authentication.jwt.JWTAuthenticationBackend",
        ...
    ]

The decoded principal is attached to ``request.jwt_principal`` for downstream use.
"""

from __future__ import annotations

from typing import Any

import jwt
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from jwt import PyJWKClient
from jwt.types import Options

from django_authz.conf import CONFIG
from django_authz.exceptions import ConfigurationError
from django_authz.models.tokens import Principal
from django_authz.utils import get_bearer_token

User = get_user_model()


class JWTAuthenticationBackend(ModelBackend):
    """Decode and validate Bearer JWTs as a Django authentication backend.

    Returns the matching User on success; ``None`` if the request carries no
    Bearer token (so other backends can run). Stores a :class:`Principal`
    instance on ``request.jwt_principal`` for downstream access.
    """

    _jwks_client: PyJWKClient | None = None

    def authenticate(self, request, **kwargs):
        if request is None:
            return None
        token = get_bearer_token(request)
        if not token:
            return None
        try:
            payload = self.decode(token)
        except Exception:
            return None

        subject = payload.get("sub")
        if not subject:
            return None

        email = payload.get("email")
        username = payload.get("preferred_username") or email or subject
        user, _ = User.objects.get_or_create(username=username, defaults={"email": email or ""})
        request.jwt_principal = Principal(
            subject=subject, email=email, username=username, claims=payload
        )
        return user

    # ---- internals -----------------------------------------------------
    def _get_jwks_client(self) -> PyJWKClient:
        if self._jwks_client is not None:
            return self._jwks_client
        jwks_url = CONFIG.JWKS_URL or self._infer_jwks_url()
        if not jwks_url:
            raise ConfigurationError("JWKS URL not configured and could not be inferred")
        # PyJWKClient caches the JWKS by default (cache_jwk_set=True)
        self._jwks_client = PyJWKClient(jwks_url)
        return self._jwks_client

    @staticmethod
    def _infer_jwks_url() -> str | None:
        if CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM:
            base = CONFIG.KEYCLOAK_URL.rstrip("/")
            return f"{base}/realms/{CONFIG.KEYCLOAK_REALM}/protocol/openid-connect/certs"
        return None

    def decode(self, token: str) -> dict[str, Any]:
        """Decode JWT with optional verification.

        When VERIFY_JWT=False, signature and audience checks are skipped (dev only).
        """
        if not CONFIG.VERIFY_JWT:
            return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

        signing_key = self._get_jwks_client().get_signing_key_from_jwt(token).key
        options = Options(
            require=["exp", "iat", "sub"],
            verify_aud=bool(CONFIG.EXPECTED_AUDIENCE),
        )
        return jwt.decode(
            token,
            key=signing_key,
            algorithms=["RS256", "RS512", "ES256", "ES384"],
            audience=CONFIG.EXPECTED_AUDIENCE,
            issuer=CONFIG.EXPECTED_ISSUER,
            options=options,
            leeway=CONFIG.JWT_LEEWAY,
        )

"""
JWT Authentication for DRF with optional signature verification via JWKS.

- By default, signature verification is **enabled** (VERIFY_JWT=True).
- JWKS URL is inferred from Keycloak settings if not explicitly provided.
- Audience and Issuer checks are optional but recommended.

This module intentionally stays framework-light so adopters can plug in
`djangorestframework-simplejwt` if they prefer its session/refresh flows.
"""
from __future__ import annotations
from typing import Any, Optional

import jwt
from jwt import PyJWKClient
from rest_framework.authentication import BaseAuthentication
from rest_framework import exceptions
from django.contrib.auth import get_user_model

from drf_authz.conf import CONFIG
from drf_authz.exceptions import ConfigurationError
from drf_authz.utils import get_bearer_token
from drf_authz.models.tokens import Principal


User = get_user_model()


class JWTAuthentication(BaseAuthentication):
    """Decode and validate Bearer JWTs.

    Returns `(user, Principal)` on success. If no Authorization header is present,
    returns `None` so other authenticators may run.
    """

    _jwks_client: Optional[PyJWKClient] = None

    def authenticate(self, request):
        token = get_bearer_token(request)
        if not token:
            return None
        try:
            payload = self.decode(token)
        except Exception as exc:  # pragma: no cover
            raise exceptions.AuthenticationFailed(str(exc))

        subject = payload.get("sub")
        if not subject:
            raise exceptions.AuthenticationFailed("Missing `sub` in token")

        email = payload.get("email")
        username = payload.get("preferred_username") or email or subject
        user, _ = User.objects.get_or_create(username=username, defaults={"email": email or ""})
        principal = Principal(subject=subject, email=email, username=username, claims=payload)
        return (user, principal)

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
    def _infer_jwks_url() -> Optional[str]:
        if CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM:
            return f"{CONFIG.KEYCLOAK_URL.rstrip('/')}/realms/{CONFIG.KEYCLOAK_REALM}/protocol/openid-connect/certs"
        return None

    def decode(self, token: str) -> dict[str, Any]:
        """Decode JWT with optional verification.

        When VERIFY_JWT=False, signature and audience checks are skipped (dev only).
        """
        if not CONFIG.VERIFY_JWT:
            return jwt.decode(token, options={"verify_signature": False, "verify_aud": False})

        signing_key = self._get_jwks_client().get_signing_key_from_jwt(token).key
        options = {"require": ["exp", "iat", "sub"], "verify_aud": bool(CONFIG.EXPECTED_AUDIENCE)}
        return jwt.decode(
            token,
            key=signing_key,
            algorithms=["RS256", "RS512", "ES256", "ES384"],
            audience=CONFIG.EXPECTED_AUDIENCE,
            issuer=CONFIG.EXPECTED_ISSUER,
            options=options,
            leeway=CONFIG.JWT_LEEWAY,
        )

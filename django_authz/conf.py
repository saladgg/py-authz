"""Centralized, typed settings with light validation.

Environment variables can be provided as ``DJANGO_AUTHZ_<KEY>``
(e.g., ``DJANGO_AUTHZ_OPENFGA_API_URL``).
"""

import contextlib
import os
from dataclasses import dataclass

from django.conf import settings

from .exceptions import ConfigurationError


@dataclass(frozen=True)
class Settings:
    # Keycloak / OIDC
    KEYCLOAK_URL: str | None = None
    KEYCLOAK_REALM: str | None = None
    KEYCLOAK_CLIENT_ID: str | None = None
    KEYCLOAK_CLIENT_SECRET: str | None = None

    # JWT verification
    VERIFY_JWT: bool = True
    JWKS_URL: str | None = None
    EXPECTED_AUDIENCE: str | None = None
    EXPECTED_ISSUER: str | None = None
    JWT_LEEWAY: int = 60  # seconds of clock skew tolerance

    # OpenFGA
    OPENFGA_API_URL: str | None = None
    OPENFGA_STORE_ID: str | None = None
    OPENFGA_MODEL_ID: str | None = None
    OPENFGA_AUTH_TOKEN: str | None = None


_default = Settings()
_user = getattr(settings, "DJANGO_AUTHZ", {})
_env = {k: os.getenv(f"DJANGO_AUTHZ_{k}") for k in Settings.__annotations__}

CONFIG = Settings(
    **{  # type: ignore[arg-type]
        k: _user.get(k)
        if _user.get(k) is not None
        else (_env.get(k) if _env.get(k) is not None else getattr(_default, k))
        for k in Settings.__annotations__
    }
)


def _infer_jwks_url(base: str | None, realm: str | None) -> str | None:
    if base and realm:
        return f"{base.rstrip('/')}/realms/{realm}/protocol/openid-connect/certs"
    return None


def validate_settings() -> None:
    """Validate critical settings at import-time for fast feedback.

    This is intentionally permissive to allow partial configuration during
    development; raise only on obviously broken states when verification is enabled.
    """
    if CONFIG.VERIFY_JWT:
        jwks = CONFIG.JWKS_URL or _infer_jwks_url(CONFIG.KEYCLOAK_URL, CONFIG.KEYCLOAK_REALM)
        if not jwks:
            raise ConfigurationError(
                "JWT verification is enabled but JWKS_URL is not set and could not be inferred."
            )

    if bool(CONFIG.OPENFGA_API_URL) ^ bool(CONFIG.OPENFGA_STORE_ID):
        # XOR — if one is set, the other must be too
        raise ConfigurationError(
            "Both OPENFGA_API_URL and OPENFGA_STORE_ID must be provided or neither."
        )


# Perform a one-time validation on import; defer errors until first use
with contextlib.suppress(ConfigurationError):
    validate_settings()

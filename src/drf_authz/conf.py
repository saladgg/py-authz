"""Centralized, typed settings with light validation.

Environment variables can be provided as `DRF-AUTHZ_<KEY>` (e.g., `DRF-AUTHZ_OPENFGA_API_URL`).
"""
import os
from dataclasses import dataclass
from typing import Optional
from django.conf import settings
from .exceptions import ConfigurationError


@dataclass(frozen=True)
class Settings:
    # Keycloak / OIDC
    KEYCLOAK_URL: Optional[str] = None
    KEYCLOAK_REALM: Optional[str] = None
    KEYCLOAK_CLIENT_ID: Optional[str] = None
    KEYCLOAK_CLIENT_SECRET: Optional[str] = None

    # JWT verification
    VERIFY_JWT: bool = True
    JWKS_URL: Optional[str] = None
    EXPECTED_AUDIENCE: Optional[str] = None
    EXPECTED_ISSUER: Optional[str] = None
    JWT_LEEWAY: int = 60  # seconds of clock skew tolerance

    # OpenFGA
    OPENFGA_API_URL: Optional[str] = None
    OPENFGA_STORE_ID: Optional[str] = None
    OPENFGA_MODEL_ID: Optional[str] = None
    OPENFGA_AUTH_TOKEN: Optional[str] = None


_default = Settings()
_user = getattr(settings, "DRF_AUTHZ", {})
_env = {k: os.getenv(f"DRF_AUTHZ_{k}") for k in Settings.__annotations__.keys()}

CONFIG = Settings(
    **{k: _user.get(k) if _user.get(k) is not None else (_env.get(k) if _env.get(k) is not None else getattr(_default, k)) for k in Settings.__annotations__.keys()}
)


def _infer_jwks_url(base: Optional[str], realm: Optional[str]) -> Optional[str]:
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
        raise ConfigurationError("Both OPENFGA_API_URL and OPENFGA_STORE_ID must be provided or neither.")


# Perform a one-time validation on import
try:
    validate_settings()
except ConfigurationError:
    # Defer raising until first use to avoid breaking Django management commands
    pass

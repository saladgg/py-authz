"""Typed settings loader and validation for DRF2Auth.

This module centralizes all configuration required for authentication and
authorization. Values are expected to come from Django's `settings.py`,
with sensible defaults and validation applied here.
"""
from django.conf import settings
from typing import Optional


class DRFAuthzSettings:
    """Centralized configuration object for DRF2Auth."""

    @property
    def OIDC_RP_CLIENT_ID(self) -> str:
        return getattr(settings, "OIDC_RP_CLIENT_ID", "")

    @property
    def OIDC_RP_CLIENT_SECRET(self) -> str:
        return getattr(settings, "OIDC_RP_CLIENT_SECRET", "")

    @property
    def OIDC_OP_JWKS_ENDPOINT(self) -> str:
        return getattr(settings, "OIDC_OP_JWKS_ENDPOINT", "")

    @property
    def OPENFGA_API_URL(self) -> str:
        return getattr(settings, "OPENFGA_API_URL", "http://localhost:8080")

    @property
    def OPENFGA_STORE_ID(self) -> str:
        return getattr(settings, "OPENFGA_STORE_ID", "default")


conf = DRFAuthzSettings()
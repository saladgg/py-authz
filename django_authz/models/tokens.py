"""Immutable token and principal dataclasses.

These are plain data containers — no ORM, no Django models.

- :class:`IDToken` — parsed claims from a Keycloak ID token.
- :class:`AccessToken` — raw access token plus commonly-used claims.
- :class:`Principal` — unified identity object attached to ``request.jwt_principal``
  by :class:`~django_authz.authentication.jwt.JWTAuthenticationBackend`.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class IDToken:
    """Parsed claims from a Keycloak (OIDC) ID token.

    Attributes:
        sub: Subject identifier — unique user ID in the IdP.
        email: User's email address (may be absent).
        preferred_username: Human-readable username from the IdP.
        realm_access: Keycloak realm-level roles mapping.
        resource_access: Keycloak client-level roles mapping.
    """

    sub: str
    email: str | None = None
    preferred_username: str | None = None
    realm_access: Mapping[str, Any] | None = None
    resource_access: Mapping[str, Any] | None = None


@dataclass(frozen=True)
class AccessToken:
    """Raw access token with commonly inspected claims.

    Attributes:
        raw: The original encoded token string (for forwarding to downstream services).
        subject: The ``sub`` claim value.
        email: The ``email`` claim value.
        scope: Space-separated OAuth2 scopes.
    """

    raw: str
    subject: str | None = None
    email: str | None = None
    scope: str | None = None


@dataclass(frozen=True)
class Principal:
    """Unified identity attached to ``request.jwt_principal`` after JWT validation.

    Created by :class:`~django_authz.authentication.jwt.JWTAuthenticationBackend`
    on every successfully authenticated request.

    Attributes:
        subject: The ``sub`` claim — canonical user identifier.
        email: User's email from the token (may be absent).
        username: The ``preferred_username`` or fallback used to look up the
            Django :class:`~django.contrib.auth.models.User`.
        claims: Full decoded JWT payload for arbitrary claim access.
    """

    subject: str
    email: str | None = None
    username: str | None = None
    claims: Mapping[str, Any] | None = None

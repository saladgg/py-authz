"""OIDC authentication backend using mozilla-django-oidc.

:class:`OIDCAuthenticationBackend` extends the upstream backend with
Keycloak-friendly defaults:

- ``create_user`` — provisions a new Django user from ``preferred_username``
  (falling back to email or ``sub``).
- ``update_user`` — keeps ``user.email`` in sync with the OIDC claim.
- ``filter_users_by_claims`` — looks up users by email (case-insensitive).

Register in settings::

    AUTHENTICATION_BACKENDS = [
        "django_authz.authentication.oidc.OIDCAuthenticationBackend",
        ...
    ]

Also add ``mozilla_django_oidc`` to ``INSTALLED_APPS`` and configure the
standard ``OIDC_RP_*`` / ``OIDC_OP_*`` settings as described in the
mozilla-django-oidc documentation.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as _OIDCBackend

User = get_user_model()


class OIDCAuthenticationBackend(_OIDCBackend):
    """OIDC backend using mozilla-django-oidc with Keycloak-friendly defaults."""

    def create_user(self, claims):  # noqa: D401
        """Create a new Django user from OIDC claims.

        Uses ``preferred_username`` as the username, falling back to ``email``
        and then ``sub``.
        """
        email = claims.get("email")
        username = claims.get("preferred_username") or email or claims.get("sub")
        return User.objects.create_user(username=username, email=email or "")

    def update_user(self, user, claims):  # noqa: D401
        """Sync ``user.email`` from the latest OIDC claims if it has changed."""
        email = claims.get("email")
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])
        return user

    def filter_users_by_claims(self, claims):  # noqa: D401
        """Look up existing users by email (case-insensitive)."""
        email = claims.get("email")
        if email:
            return User.objects.filter(email__iexact=email)
        return User.objects.none()

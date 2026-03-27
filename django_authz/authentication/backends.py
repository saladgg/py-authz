"""Shared user-provisioning helpers for authentication backends.

:func:`get_or_create_user` is the default strategy used by
:class:`~django_authz.authentication.jwt.JWTAuthenticationBackend` and
:class:`~django_authz.authentication.oidc.OIDCAuthenticationBackend` to
materialise a Django :class:`~django.contrib.auth.models.User` from a token
subject.

Override this behaviour by subclassing the relevant backend and overriding its
``authenticate`` / ``create_user`` method, or by connecting to Django's
``user_logged_in`` / ``pre_save`` signals.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model

User = get_user_model()


def get_or_create_user(subject: str, email: str | None = None, username: str | None = None):
    """Return (or create) a Django User matching the given identity claims.

    The lookup key is *username*, derived in order of preference from:
    1. the explicit *username* argument
    2. *email*
    3. the token *subject* (``sub`` claim)

    Args:
        subject: Unique identifier from the IdP (``sub`` JWT claim).
        email: User's email address (used as username fallback and stored on
            the User record).
        username: Preferred username from the IdP (``preferred_username`` claim).

    Returns:
        The matching or newly created :class:`~django.contrib.auth.models.User`
        instance.
    """
    username = username or email or subject
    user, _ = User.objects.get_or_create(username=username, defaults={"email": email or ""})
    return user

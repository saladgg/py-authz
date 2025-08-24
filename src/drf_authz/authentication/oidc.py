from __future__ import annotations
from mozilla_django_oidc.auth import OIDCAuthenticationBackend as _OIDCBackend
from django.contrib.auth import get_user_model


User = get_user_model()


class OIDCAuthenticationBackend(_OIDCBackend):
    """OIDC backend using mozilla-django-oidc with sensible defaults."""

    def create_user(self, claims):  # noqa: D401
        email = claims.get("email")
        username = claims.get("preferred_username") or email or claims.get("sub")
        return User.objects.create_user(username=username, email=email or "")

    def update_user(self, user, claims):  # noqa: D401
        email = claims.get("email")
        if email and user.email != email:
            user.email = email
            user.save(update_fields=["email"])
        return user

    def filter_users_by_claims(self, claims):  # noqa: D401
        email = claims.get("email")
        if email:
            return User.objects.filter(email__iexact=email)
        return User.objects.none()
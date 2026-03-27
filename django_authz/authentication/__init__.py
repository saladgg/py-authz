"""Public exports for ``django_authz.authentication``.

Quick reference::

    from django_authz.authentication import JWTAuthenticationBackend
    from django_authz.authentication import OIDCAuthenticationBackend
    from django_authz.authentication import KeycloakAdmin
    from django_authz.authentication import get_or_create_user
"""

from django_authz.authentication.backends import get_or_create_user
from django_authz.authentication.jwt import JWTAuthenticationBackend
from django_authz.authentication.keycloak import KeycloakAdmin
from django_authz.authentication.oidc import OIDCAuthenticationBackend

__all__ = [
    "JWTAuthenticationBackend",
    "OIDCAuthenticationBackend",
    "KeycloakAdmin",
    "get_or_create_user",
]

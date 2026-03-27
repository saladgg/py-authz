"""Keycloak client helpers.

Provides:
- :func:`get_openid` — returns a configured :class:`~keycloak.KeycloakOpenID`
  instance for user-facing OIDC operations (token exchange, introspection, etc.).
- :class:`KeycloakAdmin` — thin wrapper around :class:`~keycloak.KeycloakAdmin`
  for admin/management tasks (user lookup, role management, etc.).

Both rely on the following ``DJANGO_AUTHZ`` settings::

    DJANGO_AUTHZ = {
        "KEYCLOAK_URL": "https://keycloak.example.com",
        "KEYCLOAK_REALM": "myrealm",
        "KEYCLOAK_CLIENT_ID": "backend",
        "KEYCLOAK_CLIENT_SECRET": "...",
    }
"""

from __future__ import annotations

from keycloak import KeycloakAdmin as _KeycloakAdmin
from keycloak import KeycloakOpenID

from django_authz.conf import CONFIG


def get_openid() -> KeycloakOpenID:
    """Build and return a :class:`~keycloak.KeycloakOpenID` from current config.

    Raises:
        RuntimeError: If ``KEYCLOAK_URL``, ``KEYCLOAK_REALM``, or
            ``KEYCLOAK_CLIENT_ID`` are not configured.
    """
    if not (CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM and CONFIG.KEYCLOAK_CLIENT_ID):
        raise RuntimeError("Keycloak configuration missing (URL/REALM/CLIENT_ID)")
    return KeycloakOpenID(
        server_url=CONFIG.KEYCLOAK_URL,
        client_id=CONFIG.KEYCLOAK_CLIENT_ID,
        realm_name=CONFIG.KEYCLOAK_REALM,
        client_secret_key=CONFIG.KEYCLOAK_CLIENT_SECRET,
    )


class KeycloakAdmin:
    """Thin wrapper around python-keycloak admin for admin/management tasks.

    Authenticates using the service-account credentials configured in
    ``DJANGO_AUTHZ``, or via an existing *token* (useful in tests or when
    delegating credentials).

    Args:
        token: An optional pre-obtained admin token dict. When provided,
            username/password authentication is skipped.

    Raises:
        RuntimeError: If ``KEYCLOAK_URL`` or ``KEYCLOAK_REALM`` are not configured.

    Example::

        admin = KeycloakAdmin()
        user_info = admin.get_user("keycloak-user-uuid")
    """

    def __init__(self, token: str | None = None):
        if not (CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM):
            raise RuntimeError("Keycloak configuration missing")
        self.admin = _KeycloakAdmin(
            server_url=CONFIG.KEYCLOAK_URL,
            username=None,
            password=None,
            realm_name=CONFIG.KEYCLOAK_REALM,
            client_id=CONFIG.KEYCLOAK_CLIENT_ID,  # type: ignore[arg-type]
            client_secret_key=CONFIG.KEYCLOAK_CLIENT_SECRET,
            verify=True,
            token=token,  # type: ignore[arg-type]
        )

    def get_user(self, user_id: str):
        """Fetch a Keycloak user by their UUID.

        Args:
            user_id: The Keycloak internal user UUID.

        Returns:
            A dict of user attributes as returned by the Keycloak Admin API.
        """
        return self.admin.get_user(user_id)

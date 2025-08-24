from __future__ import annotations
from typing import Optional
from keycloak import KeycloakOpenID, KeycloakAdmin as _KeycloakAdmin
from drf_authz.conf import CONFIG


def get_openid() -> KeycloakOpenID:
    if not (CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM and CONFIG.KEYCLOAK_CLIENT_ID):
        raise RuntimeError("Keycloak configuration missing (URL/REALM/CLIENT_ID)")
    return KeycloakOpenID(
        server_url=CONFIG.KEYCLOAK_URL,
        client_id=CONFIG.KEYCLOAK_CLIENT_ID,
        realm_name=CONFIG.KEYCLOAK_REALM,
        client_secret_key=CONFIG.KEYCLOAK_CLIENT_SECRET,
    )


class KeycloakAdmin:
    """Thin wrapper around python-keycloak admin for admin/management tasks."""

    def __init__(self, token: Optional[str] = None):
        if not (CONFIG.KEYCLOAK_URL and CONFIG.KEYCLOAK_REALM):
            raise RuntimeError("Keycloak configuration missing")
        self.admin = _KeycloakAdmin(
            server_url=CONFIG.KEYCLOAK_URL,
            username=None,
            password=None,
            realm_name=CONFIG.KEYCLOAK_REALM,
            client_id=CONFIG.KEYCLOAK_CLIENT_ID,
            client_secret_key=CONFIG.KEYCLOAK_CLIENT_SECRET,
            verify=True,
            token=token,
        )

    def get_user(self, user_id: str):
        return self.admin.get_user(user_id)

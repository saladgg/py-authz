"""Tests for Keycloak client helpers: get_openid() and KeycloakAdmin."""

import pytest
from unittest.mock import MagicMock, patch

from django_authz.authentication.keycloak import KeycloakAdmin, get_openid


# ---------------------------------------------------------------------------
# get_openid
# ---------------------------------------------------------------------------


def test_get_openid_raises_when_config_missing():
    """get_openid() raises RuntimeError when KEYCLOAK_URL/REALM/CLIENT_ID absent."""
    with pytest.raises(RuntimeError, match="Keycloak configuration missing"):
        get_openid()


def test_get_openid_returns_keycloak_openid_instance(keycloak_config):
    """get_openid() builds a KeycloakOpenID using values from CONFIG."""
    mock_instance = MagicMock()
    with patch(
        "django_authz.authentication.keycloak.KeycloakOpenID", return_value=mock_instance
    ) as mock_cls:
        result = get_openid()

    assert result is mock_instance
    mock_cls.assert_called_once_with(
        server_url=keycloak_config.KEYCLOAK_URL,
        client_id=keycloak_config.KEYCLOAK_CLIENT_ID,
        realm_name=keycloak_config.KEYCLOAK_REALM,
        client_secret_key=keycloak_config.KEYCLOAK_CLIENT_SECRET,
    )


# ---------------------------------------------------------------------------
# KeycloakAdmin
# ---------------------------------------------------------------------------


def test_keycloak_admin_raises_when_config_missing():
    """KeycloakAdmin() raises RuntimeError when KEYCLOAK_URL/REALM absent."""
    with pytest.raises(RuntimeError, match="Keycloak configuration missing"):
        KeycloakAdmin()


def test_keycloak_admin_initialises_inner_client(keycloak_config):
    """KeycloakAdmin.__init__ passes correct args to the underlying _KeycloakAdmin."""
    mock_inner = MagicMock()
    with patch(
        "django_authz.authentication.keycloak._KeycloakAdmin", return_value=mock_inner
    ) as mock_cls:
        admin = KeycloakAdmin()

    assert admin.admin is mock_inner
    mock_cls.assert_called_once_with(
        server_url=keycloak_config.KEYCLOAK_URL,
        username=None,
        password=None,
        realm_name=keycloak_config.KEYCLOAK_REALM,
        client_id=keycloak_config.KEYCLOAK_CLIENT_ID,
        client_secret_key=keycloak_config.KEYCLOAK_CLIENT_SECRET,
        verify=True,
        token=None,
    )


def test_keycloak_admin_get_user_delegates_to_inner_client(keycloak_config, faker):
    """KeycloakAdmin.get_user() returns the result from the inner admin client."""
    user_id = str(faker.uuid4())
    expected = {"id": user_id, "username": faker.user_name()}

    mock_inner = MagicMock()
    mock_inner.get_user.return_value = expected

    with patch("django_authz.authentication.keycloak._KeycloakAdmin", return_value=mock_inner):
        admin = KeycloakAdmin()
        result = admin.get_user(user_id)

    assert result == expected
    mock_inner.get_user.assert_called_once_with(user_id)


def test_keycloak_admin_accepts_token_kwarg(keycloak_config):
    """KeycloakAdmin(token=...) passes the token through to _KeycloakAdmin."""
    mock_inner = MagicMock()
    with patch(
        "django_authz.authentication.keycloak._KeycloakAdmin", return_value=mock_inner
    ) as mock_cls:
        KeycloakAdmin(token="pre-obtained-token")

    _, kwargs = mock_cls.call_args
    assert kwargs["token"] == "pre-obtained-token"

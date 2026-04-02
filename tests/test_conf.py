"""Tests for django_authz.conf: Settings, validate_settings, and _infer_jwks_url."""

import pytest
from unittest.mock import patch

from django_authz.conf import Settings, _infer_jwks_url, validate_settings
from django_authz.exceptions import ConfigurationError


# ---------------------------------------------------------------------------
# _infer_jwks_url (module-level helper)
# ---------------------------------------------------------------------------


def test_infer_jwks_url_builds_correct_url():
    url = _infer_jwks_url("https://keycloak.example.com", "myrealm")
    assert url == "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"


def test_infer_jwks_url_strips_trailing_slash_from_base():
    url = _infer_jwks_url("https://keycloak.example.com/", "myrealm")
    assert url == "https://keycloak.example.com/realms/myrealm/protocol/openid-connect/certs"


def test_infer_jwks_url_returns_none_when_base_missing():
    assert _infer_jwks_url(None, "myrealm") is None


def test_infer_jwks_url_returns_none_when_realm_missing():
    assert _infer_jwks_url("https://keycloak.example.com", None) is None


def test_infer_jwks_url_returns_none_when_both_missing():
    assert _infer_jwks_url(None, None) is None


# ---------------------------------------------------------------------------
# validate_settings
# ---------------------------------------------------------------------------


def test_validate_settings_raises_when_verify_jwt_true_and_no_jwks():
    """ConfigurationError when VERIFY_JWT=True but no JWKS_URL or Keycloak config."""
    cfg = Settings(VERIFY_JWT=True)
    with patch("django_authz.conf.CONFIG", cfg):
        with pytest.raises(ConfigurationError, match="JWKS_URL"):
            validate_settings()


def test_validate_settings_passes_when_verify_jwt_true_and_jwks_url_set():
    cfg = Settings(VERIFY_JWT=True, JWKS_URL="https://example.com/jwks")
    with patch("django_authz.conf.CONFIG", cfg):
        validate_settings()  # should not raise


def test_validate_settings_passes_when_verify_jwt_true_and_keycloak_configured():
    cfg = Settings(
        VERIFY_JWT=True,
        KEYCLOAK_URL="https://keycloak.example.com",
        KEYCLOAK_REALM="myrealm",
    )
    with patch("django_authz.conf.CONFIG", cfg):
        validate_settings()  # inferred JWKS URL satisfies the check


def test_validate_settings_raises_when_only_openfga_url_set():
    """ConfigurationError when OPENFGA_API_URL is set but OPENFGA_STORE_ID is not."""
    cfg = Settings(VERIFY_JWT=False, OPENFGA_API_URL="http://fga")
    with patch("django_authz.conf.CONFIG", cfg):
        with pytest.raises(ConfigurationError, match="OPENFGA"):
            validate_settings()


def test_validate_settings_raises_when_only_store_id_set():
    """ConfigurationError when OPENFGA_STORE_ID is set but OPENFGA_API_URL is not."""
    cfg = Settings(VERIFY_JWT=False, OPENFGA_STORE_ID="store-1")
    with patch("django_authz.conf.CONFIG", cfg):
        with pytest.raises(ConfigurationError, match="OPENFGA"):
            validate_settings()


def test_validate_settings_passes_when_both_openfga_values_set():
    cfg = Settings(
        VERIFY_JWT=False,
        OPENFGA_API_URL="http://fga",
        OPENFGA_STORE_ID="store-1",
    )
    with patch("django_authz.conf.CONFIG", cfg):
        validate_settings()  # should not raise


def test_validate_settings_passes_when_neither_openfga_value_set():
    cfg = Settings(VERIFY_JWT=False)
    with patch("django_authz.conf.CONFIG", cfg):
        validate_settings()  # both None → XOR is False → no error


# ---------------------------------------------------------------------------
# Settings dataclass
# ---------------------------------------------------------------------------


def test_settings_defaults():
    cfg = Settings()
    assert cfg.VERIFY_JWT is True
    assert cfg.JWT_LEEWAY == 60
    assert cfg.KEYCLOAK_URL is None
    assert cfg.OPENFGA_API_URL is None

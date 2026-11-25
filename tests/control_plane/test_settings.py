"""Tests for py_authz.control_plane.settings.ControlPlaneSettings (CP-1)."""

import os

import pytest

from py_authz.control_plane.settings import ControlPlaneSettings
from py_authz.core.exceptions import ConfigurationError

_REQUIRED_ENV = {
    "FGA_API_URL": "http://fga.local",
    "CONTROL_PLANE_FGA_STORE_ID": "store1",
    "CONTROL_PLANE_POSTGRES_DSN": "postgres://fake",
    "CONTROL_PLANE_OIDC_ISSUER": "https://issuer.local",
    "CONTROL_PLANE_OIDC_AUDIENCE": "aud",
}


def _set_env(monkeypatch, overrides=None):
    # Start from a clean slate: a developer shell that exports `.env`
    # (e.g. CONTROL_PLANE_REDIS_URL) must not leak into these assertions.
    for key in list(os.environ):
        if key.startswith("CONTROL_PLANE_"):
            monkeypatch.delenv(key)
    env = {**_REQUIRED_ENV, **(overrides or {})}
    for key, value in env.items():
        monkeypatch.setenv(key, value)


def test_from_env_reads_required_vars(monkeypatch):
    _set_env(monkeypatch)

    settings = ControlPlaneSettings.from_env()

    assert settings.fga_api_url == "http://fga.local"
    assert settings.rbac_fga_api_url == "http://fga.local"  # defaults to fga_api_url
    assert settings.rbac_fga_store_id == "store1"
    assert settings.postgres_dsn == "postgres://fake"


def test_from_env_missing_required_var_raises_configuration_error(monkeypatch):
    monkeypatch.delenv("FGA_API_URL", raising=False)

    with pytest.raises(ConfigurationError):
        ControlPlaneSettings.from_env()


def test_from_env_rbac_api_url_overridable_independently(monkeypatch):
    _set_env(monkeypatch, {"CONTROL_PLANE_FGA_API_URL": "http://rbac.local"})

    settings = ControlPlaneSettings.from_env()

    assert settings.fga_api_url == "http://fga.local"
    assert settings.rbac_fga_api_url == "http://rbac.local"


def test_from_env_optional_fields_default_sensibly(monkeypatch):
    _set_env(monkeypatch)

    settings = ControlPlaneSettings.from_env()

    assert settings.redis_url is None
    assert settings.break_glass_subject is None
    assert settings.max_cached_tenants == 1000
    assert settings.migration_concurrency == 10

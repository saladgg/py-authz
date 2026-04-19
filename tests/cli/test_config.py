import pytest

from py_authz.cli.config import get_env


def test_get_env_returns_value(monkeypatch):
    monkeypatch.setenv("FGA_STORE_ID", "store-abc")

    assert get_env("FGA_STORE_ID") == "store-abc"


def test_get_env_returns_default(monkeypatch):
    monkeypatch.delenv("UNSET_VAR", raising=False)

    assert get_env("UNSET_VAR", default="fallback") == "fallback"


def test_get_env_required_raises(monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)

    with pytest.raises(RuntimeError, match="Missing required"):
        get_env("MISSING_VAR", required=True)

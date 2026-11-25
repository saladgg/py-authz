import pytest

from py_authz.core.exceptions import ConfigurationError
from py_authz.utils.modules import load_module


def test_load_module_imports_valid_module():
    load_module("py_authz.core.types")


def test_load_module_raises_on_missing_module():
    with pytest.raises(ConfigurationError, match="Failed to import"):
        load_module("nonexistent.module.path.xyz")

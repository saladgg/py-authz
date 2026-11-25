"""
DX3-6: every numbered example must at least import, so drift like the
README snippet in DX3-9 (a renamed class, a moved module) fails CI. The
live suite runs a subset end to end (`tests/live/test_examples_live.py`).
"""

import importlib.util
import pathlib
import sys

import pytest

EXAMPLES = sorted(pathlib.Path(__file__).parent.parent.joinpath("examples").glob("[0-9]*.py"))

#: Examples 05 and 14 read required settings at import time, by design.
_DUMMY_ENV = {
    "FGA_API_URL": "http://localhost:1",
    "FGA_STORE_ID": "store",
    "FGA_MODEL_ID": "model",
    "KEYCLOAK_ISSUER": "http://localhost:1/realms/x",
    "KEYCLOAK_AUDIENCE": "aud",
    "CONTROL_PLANE_FGA_STORE_ID": "rbac",
    "CONTROL_PLANE_POSTGRES_DSN": "postgres://u:p@localhost:1/db",
    "CONTROL_PLANE_OIDC_ISSUER": "http://localhost:1/realms/x",
    "CONTROL_PLANE_OIDC_AUDIENCE": "aud",
}


def test_examples_are_discovered():
    assert len(EXAMPLES) >= 14


@pytest.mark.parametrize("path", EXAMPLES, ids=lambda p: p.stem)
def test_example_imports(path, monkeypatch):
    for key, value in _DUMMY_ENV.items():
        monkeypatch.setenv(key, value)
    name = f"_example_{path.stem}"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, module)
    spec.loader.exec_module(module)

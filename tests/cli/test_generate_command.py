import json

import pytest

from py_authz.cli.commands.generate import generate_command
from py_authz.core.exceptions import ModelValidationError
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry


def test_generate_command_writes_to_file(tmp_path):
    out = tmp_path / "model.json"

    generate_command(output=str(out))

    data = json.loads(out.read_text())
    assert data["schema_version"] == "1.1"
    assert "type_definitions" in data


def test_generate_command_prints_to_stdout(capsys):
    generate_command(output=None)

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == "1.1"


# ----------------------------------------------------------------------
# Regression coverage for DX-5: `generate-model` now validates by default
# (matching `sync`, which always has), so a malformed/cyclic model fails
# fast at generation time instead of being committed or fed into CI.
# ----------------------------------------------------------------------


class CyclicA(ResourceModel):
    type = "dx5_cyclic_a"
    b = Relation("b", union=["c"])
    c = Relation("c", union=["b"])


@pytest.fixture(autouse=True)
def _remove_cyclic_model_from_global_registry():
    """
    `generate_model()` always reads the module-global `registry` (there's
    no way to inject a scoped one), so a genuinely *invalid* — not just
    unused — registered type would otherwise leak into every other test
    in the session that calls `generate_command()`/`generate_model()`
    with default validation, however unrelated. Deliberately cleaned up,
    unlike the benign (non-cyclic) test models other files register.
    """
    yield
    registry._models.pop(CyclicA.type, None)


def test_generate_command_validates_by_default_and_rejects_cycles():
    registry.register(CyclicA)

    with pytest.raises(ModelValidationError, match="Circular"):
        generate_command(output=None)


def test_generate_command_no_validate_skips_validation(capsys):
    registry.register(CyclicA)

    # Must not raise, even though the registered model is cyclic.
    generate_command(output=None, validate=False)

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["schema_version"] == "1.1"

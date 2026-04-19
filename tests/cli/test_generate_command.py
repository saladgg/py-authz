import json

from py_authz.cli.commands.generate import generate_command


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

import sys

import pytest

from py_authz.cli import main as main_module


@pytest.fixture(autouse=True)
def patch_cli_entry(monkeypatch):
    calls = {"generate": [], "sync": [], "load_module": []}

    def fake_generate(output=None):
        calls["generate"].append(output)

    async def fake_sync(**kwargs):
        calls["sync"].append(kwargs)

    def fake_load(module_path):
        calls["load_module"].append(module_path)

    def fake_anyio_run(func, **kwargs):
        import asyncio

        asyncio.run(func(**kwargs))

    monkeypatch.setattr(main_module, "generate_command", fake_generate)
    monkeypatch.setattr(main_module, "sync_command", fake_sync)
    monkeypatch.setattr(main_module, "load_module", fake_load)
    monkeypatch.setattr(main_module.anyio, "run", fake_anyio_run)
    return calls


def _run_main(argv):
    sys.argv = ["py-authz", *argv]
    main_module.main()


def test_main_generate_model_invokes_command_with_output(patch_cli_entry, tmp_path):
    out = tmp_path / "out.json"

    _run_main(["generate-model", "-o", str(out)])

    assert patch_cli_entry["generate"] == [str(out)]


def test_main_generate_model_loads_module_when_provided(patch_cli_entry):
    _run_main(["generate-model", "--module", "some.module"])

    assert patch_cli_entry["load_module"] == ["some.module"]
    assert patch_cli_entry["generate"] == [None]


def test_main_sync_invokes_sync_command(patch_cli_entry):
    _run_main(
        [
            "sync",
            "--store-id",
            "s",
            "--api-url",
            "http://fake",
            "--model-id",
            "m",
            "--force",
        ]
    )

    assert patch_cli_entry["sync"] == [
        {"store_id": "s", "api_url": "http://fake", "model_id": "m", "force": True}
    ]


def test_main_no_command_prints_help(patch_cli_entry, capsys):
    _run_main([])

    captured = capsys.readouterr()
    assert "usage" in captured.out.lower()
    assert patch_cli_entry["generate"] == []
    assert patch_cli_entry["sync"] == []

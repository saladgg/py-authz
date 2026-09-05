import asyncio
import sys

import pytest

from py_authz.cli import main as main_module
from py_authz.core.exceptions import (
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    InvalidAuthzRequest,
)


@pytest.fixture(autouse=True)
def patch_cli_entry(monkeypatch):
    calls = {"generate": [], "sync": [], "migrate": [], "load_module": [], "setup_logging": []}

    def fake_generate(output=None, *, validate=True):
        calls["generate"].append({"output": output, "validate": validate})

    async def fake_sync(**kwargs):
        calls["sync"].append(kwargs)

    async def fake_migrate(**kwargs):
        calls["migrate"].append(kwargs)

    def fake_load(module_path):
        calls["load_module"].append(module_path)

    def fake_setup_logging(level):
        calls["setup_logging"].append(level)

    def fake_anyio_run(func):
        """
        Mirrors real `anyio.run`'s actual contract: a single callable,
        invoked with no further arguments — real `anyio.run(func, *args,
        backend=..., backend_options=...)` does NOT forward keyword
        arguments to `func`. `cli/main.py` bakes every argument into a
        zero-arg `functools.partial` before calling `anyio.run`, which is
        exactly what this fake expects; a version of this fake that
        accepted `**kwargs` and forwarded them to `func` (the original
        shape of this fixture) would have masked the real bug that
        shipped here — see the regression tests below.
        """
        return asyncio.run(func())

    monkeypatch.setattr(main_module, "generate_command", fake_generate)
    monkeypatch.setattr(main_module, "sync_command", fake_sync)
    monkeypatch.setattr(main_module, "migrate_command", fake_migrate)
    monkeypatch.setattr(main_module, "load_module", fake_load)
    monkeypatch.setattr(main_module, "setup_logging", fake_setup_logging)
    monkeypatch.setattr(main_module.anyio, "run", fake_anyio_run)
    return calls


def _run_main(argv):
    sys.argv = ["py-authz", *argv]
    main_module.main()


def test_main_generate_model_invokes_command_with_output(patch_cli_entry, tmp_path):
    out = tmp_path / "out.json"

    _run_main(["generate-model", "-o", str(out)])

    assert patch_cli_entry["generate"] == [{"output": str(out), "validate": True}]


def test_main_generate_model_loads_module_when_provided(patch_cli_entry):
    _run_main(["generate-model", "--module", "some.module"])

    assert patch_cli_entry["load_module"] == ["some.module"]
    assert patch_cli_entry["generate"] == [{"output": None, "validate": True}]


def test_main_generate_model_no_validate_flag(patch_cli_entry):
    """Regression test for DX-5: `--no-validate` must actually reach
    `generate_command(validate=False)`."""
    _run_main(["generate-model", "--no-validate"])

    assert patch_cli_entry["generate"] == [{"output": None, "validate": False}]


def test_main_sync_invokes_sync_command(patch_cli_entry):
    """
    Regression test: `anyio.run(sync_command, store_id=..., ...)` — kwargs
    passed directly to `anyio.run` itself — raised `TypeError` the moment
    this command was actually run, since real `anyio.run` has no such
    kwarg-forwarding behavior. This test's fake `anyio.run` now mirrors
    the real contract (see `fake_anyio_run`'s docstring above), so it
    would have caught that.
    """
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
        {
            "store_id": "s",
            "api_url": "http://fake",
            "model_id": "m",
            "force": True,
            "json_output": False,
        }
    ]


def test_main_sync_json_flag_forwards_json_output(patch_cli_entry):
    """Regression test for DX2-15: `--json` must reach `sync_command`."""
    _run_main(["sync", "--api-url", "http://fake", "--store-id", "s", "--json"])

    assert patch_cli_entry["sync"] == [
        {
            "store_id": "s",
            "api_url": "http://fake",
            "model_id": None,
            "force": False,
            "json_output": True,
        }
    ]


def test_main_migrate_invokes_migrate_command(patch_cli_entry):
    _run_main(
        [
            "migrate",
            "--all-tenants",
            "--api-url",
            "http://fake",
            "--backend",
            "redis",
            "--conn",
            "redis://fake",
        ]
    )

    assert patch_cli_entry["migrate"] == [
        {
            "api_url": "http://fake",
            "backend": "redis",
            "conn": "redis://fake",
            "tenant_ids": None,
            "dry_run": False,
            "yes": False,
            "json_output": False,
        }
    ]


def test_main_migrate_with_specific_tenants(patch_cli_entry):
    _run_main(["migrate", "--tenant", "t1", "--tenant", "t2", "--api-url", "http://fake"])

    assert patch_cli_entry["migrate"] == [
        {
            "api_url": "http://fake",
            "backend": "memory",
            "conn": None,
            "tenant_ids": ["t1", "t2"],
            "dry_run": False,
            "yes": False,
            "json_output": False,
        }
    ]


def test_main_migrate_forwards_dry_run_and_yes_flags(patch_cli_entry):
    _run_main(["migrate", "--all-tenants", "--api-url", "http://fake", "--dry-run", "--yes"])

    assert patch_cli_entry["migrate"] == [
        {
            "api_url": "http://fake",
            "backend": "memory",
            "conn": None,
            "tenant_ids": None,
            "dry_run": True,
            "yes": True,
            "json_output": False,
        }
    ]


def test_main_migrate_json_flag_forwards_json_output(patch_cli_entry):
    """Regression test for DX2-15: `--json` must reach `migrate_command`."""
    _run_main(["migrate", "--tenant", "t1", "--api-url", "http://fake", "--json"])

    assert patch_cli_entry["migrate"] == [
        {
            "api_url": "http://fake",
            "backend": "memory",
            "conn": None,
            "tenant_ids": ["t1"],
            "dry_run": False,
            "yes": False,
            "json_output": True,
        }
    ]


def test_main_migrate_requires_all_tenants_or_tenant_flag(patch_cli_entry, capsys):
    with pytest.raises(SystemExit):
        _run_main(["migrate", "--api-url", "http://fake"])

    assert patch_cli_entry["migrate"] == []
    captured = capsys.readouterr()
    assert "--all-tenants" in captured.err


def test_main_migrate_loads_module_when_provided(patch_cli_entry):
    _run_main(["migrate", "--all-tenants", "--module", "some.module"])

    assert patch_cli_entry["load_module"] == ["some.module"]


def test_main_version_flag_prints_version_and_exits_cleanly(patch_cli_entry, capsys):
    """
    Regression test for DX2-13: `--version` must actually work (it used
    to raise "unrecognized arguments: --version") and exit with code 0.
    """
    with pytest.raises(SystemExit) as exc_info:
        _run_main(["--version"])

    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "py-authz" in captured.out


def test_main_no_command_prints_help(patch_cli_entry, capsys):
    _run_main([])

    captured = capsys.readouterr()
    assert "usage" in captured.out.lower()
    assert patch_cli_entry["generate"] == []
    assert patch_cli_entry["sync"] == []
    assert patch_cli_entry["migrate"] == []


def test_main_defaults_to_info_logging(patch_cli_entry):
    """
    Regression test for ARCH-6: `TenantManager`/`MigrationManager` log
    their progress via the standard `logging` module, which is invisible
    without a configured handler — the CLI must configure one.
    """
    import logging

    _run_main(["generate-model"])

    assert patch_cli_entry["setup_logging"] == [logging.INFO]


def test_main_verbose_flag_enables_debug_logging(patch_cli_entry):
    import logging

    _run_main(["--verbose", "generate-model"])

    assert patch_cli_entry["setup_logging"] == [logging.DEBUG]


@pytest.mark.parametrize(
    ("exc_cls", "expected_code"),
    [
        (ConfigurationError, 2),
        (InvalidAuthzRequest, 3),
        (ExternalServiceError, 4),
        (AuthzError, 1),  # base class fallback
    ],
)
def test_main_maps_authz_errors_to_exit_codes(
    patch_cli_entry, capsys, monkeypatch, exc_cls, expected_code
):
    """
    Regression test for DX-6: an `AuthzError` from a command must produce a
    friendly message and a specific, documented exit code — not a raw
    traceback and a generic non-zero exit.
    """

    def fake_generate(output=None, *, validate=True):
        raise exc_cls("boom")

    monkeypatch.setattr(main_module, "generate_command", fake_generate)

    with pytest.raises(SystemExit) as exc_info:
        _run_main(["generate-model"])

    assert exc_info.value.code == expected_code
    captured = capsys.readouterr()
    assert "boom" in captured.err
    assert "Error:" in captured.err


def test_main_does_not_swallow_non_authz_exceptions(patch_cli_entry, monkeypatch):
    """
    A bug that isn't a categorized `AuthzError` must still propagate with
    its full traceback — DX-6 only asks for friendly handling of known
    failure classes, not blanket exception suppression.
    """

    def fake_generate(output=None, *, validate=True):
        raise RuntimeError("not an AuthzError")

    monkeypatch.setattr(main_module, "generate_command", fake_generate)

    with pytest.raises(RuntimeError, match="not an AuthzError"):
        _run_main(["generate-model"])

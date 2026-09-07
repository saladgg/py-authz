"""Tests for py_authz.control_plane.__main__ — `python -m
py_authz.control_plane`'s dev-run entrypoint. `uvicorn.run()` is
imported locally inside `main()` (not at module level), so it's faked
via `sys.modules` rather than a regular `monkeypatch.setattr` on an
already-imported name."""

import sys
import types

import pytest

from py_authz.control_plane.__main__ import main


@pytest.fixture
def fake_uvicorn(monkeypatch):
    calls = []

    def fake_run(app, **kwargs):
        calls.append((app, kwargs))

    module = types.ModuleType("uvicorn")
    module.run = fake_run
    monkeypatch.setitem(sys.modules, "uvicorn", module)
    return calls


def test_main_runs_uvicorn_against_the_app_factory_with_env_defaults(fake_uvicorn, monkeypatch):
    monkeypatch.delenv("CONTROL_PLANE_HOST", raising=False)
    monkeypatch.delenv("CONTROL_PLANE_PORT", raising=False)

    main()

    assert len(fake_uvicorn) == 1
    app, kwargs = fake_uvicorn[0]
    assert app == "py_authz.control_plane.app:create_app"
    assert kwargs == {"factory": True, "host": "127.0.0.1", "port": 8000}


def test_main_reads_host_and_port_from_the_environment(fake_uvicorn, monkeypatch):
    monkeypatch.setenv("CONTROL_PLANE_HOST", "0.0.0.0")  # noqa: S104 — asserting pass-through only
    monkeypatch.setenv("CONTROL_PLANE_PORT", "9000")

    main()

    _, kwargs = fake_uvicorn[0]
    assert kwargs["host"] == "0.0.0.0"  # noqa: S104 — asserting pass-through only, nothing binds
    assert kwargs["port"] == 9000

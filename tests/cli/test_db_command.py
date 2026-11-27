"""Tests for `py-authz db migrate` / `py-authz db status` (REL3-10)."""

import asyncio
import json
import sys
from datetime import UTC, datetime

import pytest

from py_authz.cli import main as main_module
from py_authz.cli.commands import db as db_module
from py_authz.core.exceptions import ConfigurationError, ExternalServiceError
from py_authz.storage import schema as schema_module
from py_authz.storage.schema import MigrationState

APPLIED_AT = datetime(2026, 11, 26, tzinfo=UTC)


@pytest.fixture
def fake_schema(monkeypatch):
    calls: dict = {"apply": [], "status": []}
    state = {"applied": ["0009_audit_logs_store_id"], "pending": ["0010_x"], "error": None}

    async def apply_schema(dsn, *, lock_timeout):
        calls["apply"].append((dsn, lock_timeout))
        if state["error"]:
            raise state["error"]
        return state["applied"]

    async def schema_status(dsn):
        calls["status"].append(dsn)
        return [
            MigrationState("0009_audit_logs_store_id", APPLIED_AT),
            *(MigrationState(v, None) for v in state["pending"]),
        ]

    monkeypatch.setattr(schema_module, "apply_schema", apply_schema)
    monkeypatch.setattr(schema_module, "schema_status", schema_status)
    monkeypatch.setattr(main_module.anyio, "run", lambda func: asyncio.run(func()))
    monkeypatch.setattr(main_module, "setup_logging", lambda level: None)
    return calls, state


def _main(*argv):
    sys.argv = ["py-authz", *argv]
    main_module.main()


def test_migrate_uses_dsn_flag_and_lock_timeout(fake_schema, capsys):
    calls, _ = fake_schema

    _main("db", "migrate", "--dsn", "postgres://x", "--lock-timeout", "12")

    assert calls["apply"] == [("postgres://x", 12.0)]
    assert "applied 0009_audit_logs_store_id" in capsys.readouterr().out


def test_migrate_falls_back_to_postgres_dsn_env_and_reports_up_to_date(
    fake_schema, capsys, monkeypatch
):
    calls, state = fake_schema
    state["applied"] = []
    monkeypatch.setenv("POSTGRES_DSN", "postgres://env")

    _main("db", "migrate")

    assert calls["apply"][0][0] == "postgres://env"
    assert "up to date" in capsys.readouterr().out


def test_migrate_json(fake_schema, capsys):
    _main("db", "migrate", "--dsn", "postgres://x", "--json")

    assert json.loads(capsys.readouterr().out) == {"applied": ["0009_audit_logs_store_id"]}


def test_missing_dsn_exits_2(fake_schema, monkeypatch, capsys):
    monkeypatch.delenv("POSTGRES_DSN", raising=False)

    with pytest.raises(SystemExit) as exc:
        _main("db", "migrate")

    assert exc.value.code == 2
    assert "POSTGRES_DSN" in capsys.readouterr().err


def test_postgres_errors_exit_4_without_a_traceback(fake_schema, capsys):
    _, state = fake_schema
    state["error"] = OSError("connection refused")

    with pytest.raises(SystemExit) as exc:
        _main("db", "migrate", "--dsn", "postgres://x")

    assert exc.value.code == 4
    assert "connection refused" in capsys.readouterr().err


def test_status_lists_applied_and_pending(fake_schema, capsys):
    _main("db", "status", "--dsn", "postgres://x")

    out = capsys.readouterr().out
    assert "0009_audit_logs_store_id" in out and APPLIED_AT.isoformat() in out
    assert "0010_x" in out and "pending" in out


def test_status_check_exits_1_when_pending(fake_schema):
    with pytest.raises(SystemExit) as exc:
        _main("db", "status", "--dsn", "postgres://x", "--check")

    assert exc.value.code == 1


def test_status_check_exits_0_when_current_and_prints_json(fake_schema, capsys):
    _, state = fake_schema
    state["pending"] = []

    _main("db", "status", "--dsn", "postgres://x", "--check", "--json")

    out = json.loads(capsys.readouterr().out)
    assert out["pending"] == []
    assert out["migrations"][0]["applied_at"] == APPLIED_AT.isoformat()


def test_db_requires_a_subcommand(fake_schema):
    with pytest.raises(SystemExit) as exc:
        _main("db")

    assert exc.value.code == 2


def test_missing_postgres_extra_is_a_configuration_error(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_asyncpg(name, *args, **kwargs):
        if name == "asyncpg":
            raise ImportError("no asyncpg")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", no_asyncpg)

    with pytest.raises(ConfigurationError, match="postgres extra"):
        db_module._schema()


def test_db_call_wraps_postgres_errors():
    import asyncpg

    async def boom(dsn):
        raise asyncpg.PostgresError("syntax")

    with pytest.raises(ExternalServiceError):
        asyncio.run(db_module._db_call(boom, "postgres://x"))

"""`py-authz db migrate` / `py-authz db status` (REL3-10)."""

import json
from collections.abc import Awaitable, Callable

from py_authz.cli.config import get_env
from py_authz.core.exceptions import ConfigurationError, ExternalServiceError


def _resolve_dsn(dsn: str | None) -> str:
    return dsn or get_env("POSTGRES_DSN", required=True)


def _schema():
    # Imported lazily: asyncpg comes with the `postgres` extra, and the
    # rest of the CLI must work without it.
    try:
        import asyncpg

        from py_authz.storage import schema
    except ImportError as exc:
        raise ConfigurationError(
            "py-authz db needs the postgres extra: pip install 'py-authz[postgres,cli]'"
        ) from exc
    return asyncpg, schema


async def _db_call[T](fn: Callable[[str], Awaitable[T]], dsn: str) -> T:
    asyncpg, _ = _schema()
    # Connection and SQL failures become `ExternalServiceError`, so the
    # CLI prints one line and exits 4 instead of dumping a traceback.
    try:
        return await fn(dsn)
    except (OSError, asyncpg.PostgresError) as exc:
        raise ExternalServiceError(f"Postgres error: {exc}") from exc


async def db_migrate_command(
    *, dsn: str | None = None, lock_timeout: float = 300.0, json_output: bool = False
) -> None:
    applied = await _db_call(
        lambda d: _schema()[1].apply_schema(d, lock_timeout=lock_timeout), _resolve_dsn(dsn)
    )
    if json_output:
        print(json.dumps({"applied": applied}))
    elif applied:
        for version in applied:
            print(f"applied {version}")
    else:
        print("schema is up to date")


async def db_status_command(
    *, dsn: str | None = None, json_output: bool = False, check: bool = False
) -> int:
    """Returns the exit code: 1 with `check` when migrations are pending."""
    states = await _db_call(lambda d: _schema()[1].schema_status(d), _resolve_dsn(dsn))
    pending = [s.version for s in states if not s.applied]
    if json_output:
        print(
            json.dumps(
                {
                    "migrations": [
                        {
                            "version": s.version,
                            "applied_at": s.applied_at.isoformat() if s.applied_at else None,
                        }
                        for s in states
                    ],
                    "pending": pending,
                }
            )
        )
    else:
        for s in states:
            when = s.applied_at.isoformat() if s.applied_at else "pending"
            print(f"{s.version:<40} {when}")
    return 1 if check and pending else 0

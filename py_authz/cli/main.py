import argparse
import functools
import logging
import os
import sys
from importlib.metadata import PackageNotFoundError, version

import anyio

from py_authz.cli.commands.db import db_migrate_command, db_status_command
from py_authz.cli.commands.generate import generate_command
from py_authz.cli.commands.migrate import migrate_command
from py_authz.cli.commands.sync import sync_command
from py_authz.core.exceptions import (
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    InvalidAuthzRequest,
    TenantNotFoundError,
)
from py_authz.core.logging import setup_logging
from py_authz.utils.modules import load_module

logger = logging.getLogger("py_authz.cli")

# Ordered most-specific-first: `ExternalServiceError`/`ConfigurationError`/
# `InvalidAuthzRequest` all inherit from `AuthzError`, so an `isinstance`
# check further down this list would never be reached if a more general
# one came first. Distinct exit codes let an automated pipeline branch on
# failure class (e.g. "retry on 4, don't retry on 2") without parsing text.
_EXIT_CODES: list[tuple[type[AuthzError], int]] = [
    (ConfigurationError, 2),
    (InvalidAuthzRequest, 3),
    (TenantNotFoundError, 3),  # a bad --tenant argument is an invalid-request shape too
    (ExternalServiceError, 4),
]


def _exit_code_for(exc: AuthzError) -> int:
    for exc_type, code in _EXIT_CODES:
        if isinstance(exc, exc_type):
            return code
    return 1  # any other AuthzError


def _package_version() -> str:
    """
    `importlib.metadata.version('py-authz')` — falls back to a clearly
    labeled placeholder in a source checkout that was never `pip
    install`-ed (editable or otherwise), e.g. running `python -m
    py_authz.cli.main` straight out of a git clone with no build step,
    rather than letting `--version` itself crash (see DX2-13).
    """
    try:
        return version("py-authz")
    except PackageNotFoundError:
        return "unknown (not installed)"


# Every env var any CLI command falls back to, for `--help`'s epilog
# (see DX2-16) — kept as one list so the epilog and any future
# per-argument `help=` text can't drift out of sync with each other.
_ENV_VARS = """\
Environment variables (used as fallbacks — see "Config precedence" below):
  FGA_STORE_ID        OpenFGA store ID                 (sync)
  FGA_API_URL         OpenFGA API base URL              (sync, migrate)
  FGA_MODEL_ID        OpenFGA authorization model ID    (sync)
  TENANT_STORE_BACKEND  postgres | redis | memory        (migrate --backend)
  TENANT_STORE_CONN   Postgres DSN / Redis URL          (migrate --backend postgres|redis)
  POSTGRES_DSN        Postgres DSN                      (db migrate, db status)
"""

_EPILOG = f"""\
Examples:
  # Generate the OpenFGA schema from your registered models
  py-authz generate-model --module myapp.authz.models --output model.json

  # Diff + sync to a running OpenFGA instance
  py-authz sync --module myapp.authz.models --api-url http://localhost:8082 --store-id $STORE_ID

  # Roll the current model out to every known tenant, previewing first
  py-authz migrate --backend postgres --module myapp.authz.models --all-tenants --dry-run
  py-authz migrate --backend postgres --module myapp.authz.models --all-tenants --yes

  # Migrate just one tenant, with a machine-readable summary for CI
  py-authz migrate --backend postgres --tenant acme-corp --api-url http://localhost:8082 --json

  # Apply pending database migrations (a deploy step; see docs/upgrading.md)
  py-authz db migrate --dsn $POSTGRES_DSN

{_ENV_VARS}
Config precedence: an explicit CLI flag always wins over its matching env
var above (e.g. `--api-url` overrides $FGA_API_URL); a required value
missing from both raises a ConfigurationError (exit code 2).
"""


def main():
    parser = argparse.ArgumentParser(
        prog="py-authz",
        description="CLI tooling for py-authz: generate, sync, and migrate OpenFGA models, "
        "and migrate its Postgres schema.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"py-authz {_package_version()}",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging (e.g. tenant provisioning/migration progress)",
    )
    subparsers = parser.add_subparsers(dest="command", help="Subcommand to run")

    # -------------------------------------------------
    # generate-model
    # -------------------------------------------------
    gen_parser = subparsers.add_parser(
        "generate-model",
        help="Generate the OpenFGA authorization model JSON from registered Python models",
        description="Generate the OpenFGA authorization model JSON from registered Python models.",
        epilog="Example:\n  py-authz generate-model --module myapp.authz.models -o model.json",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    gen_parser.add_argument(
        "--output",
        "-o",
        help="Output file to write the generated model JSON to (default: stdout)",
        default=None,
    )
    gen_parser.add_argument(
        "--module",
        help="Python module path to import first, so its @ResourceModel classes register "
        "(e.g. myapp.authz.models)",
        required=False,
    )
    gen_parser.add_argument(
        "--no-validate",
        action="store_true",
        help="Skip DefaultModelValidator (useful while iterating on an in-progress model)",
    )

    # -------------------------------------------------
    # sync
    # -------------------------------------------------

    sync_parser = subparsers.add_parser(
        "sync",
        help="Diff the current model against OpenFGA and upload it if it changed",
        description="Diff the current model against a running OpenFGA instance and upload it "
        "only if it changed.",
        epilog=(
            "Example:\n"
            "  py-authz sync --module myapp.authz.models --api-url http://localhost:8082 "
            "--store-id $STORE_ID\n\n" + _ENV_VARS
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    sync_parser.add_argument(
        "--store-id",
        required=False,
        help="OpenFGA store ID (env: FGA_STORE_ID)",
    )
    sync_parser.add_argument(
        "--api-url",
        required=False,
        help="OpenFGA API base URL, e.g. http://localhost:8082 (env: FGA_API_URL)",
    )
    sync_parser.add_argument(
        "--model-id",
        required=False,
        help="Current authorization model ID, used to detect drift (env: FGA_MODEL_ID)",
    )
    sync_parser.add_argument(
        "--force",
        action="store_true",
        help="Force upload even if model unchanged",
    )
    sync_parser.add_argument(
        "--module",
        help="Python module path to import first, so its @ResourceModel classes register "
        "(e.g. myapp.authz.models)",
        required=False,
    )
    sync_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print a machine-readable JSON summary instead of a human-readable line",
    )

    # -------------------------------------------------
    # migrate
    # -------------------------------------------------

    migrate_parser = subparsers.add_parser(
        "migrate",
        help="Roll a model change out across tenants",
        description="Roll the current model out across one or all tenants known to a "
        "tenant-store backend.",
        epilog=(
            "Examples:\n"
            "  py-authz migrate --backend postgres --module myapp.authz.models \\\n"
            "      --all-tenants --dry-run\n"
            "  py-authz migrate --backend postgres --module myapp.authz.models \\\n"
            "      --all-tenants --yes\n"
            "  py-authz migrate --backend postgres --tenant acme-corp \\\n"
            "      --api-url http://localhost:8082 --json\n\n" + _ENV_VARS
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    migrate_parser.add_argument(
        "--api-url",
        required=False,
        help="OpenFGA API base URL, e.g. http://localhost:8082 (env: FGA_API_URL)",
    )
    migrate_parser.add_argument(
        "--backend",
        choices=["memory", "postgres", "redis"],
        default=None,
        help=(
            "Where tenant->store mappings and model versions are persisted "
            "(env: TENANT_STORE_BACKEND). Required: there is no default, since "
            "the in-memory backend starts empty and would 'migrate' nothing "
            "while exiting 0 (DX3-8). `memory` is for local testing only."
        ),
    )
    migrate_parser.add_argument(
        "--allow-empty",
        action="store_true",
        help="Exit 0 when --all-tenants finds no tenants (default: exit non-zero)",
    )
    migrate_parser.add_argument(
        "--conn",
        required=False,
        help=(
            "Connection string for --backend postgres|redis (Postgres DSN or Redis URL); "
            "falls back to the TENANT_STORE_CONN env var"
        ),
    )
    migrate_parser.add_argument(
        "--all-tenants",
        action="store_true",
        help="Migrate every tenant the backend knows about",
    )
    migrate_parser.add_argument(
        "--tenant",
        action="append",
        dest="tenant_ids",
        help="Migrate a specific tenant (repeatable). Default is --all-tenants.",
    )
    migrate_parser.add_argument(
        "--module",
        help="Python module path to import first, so its @ResourceModel classes register "
        "(e.g. myapp.authz.models)",
        required=False,
    )
    migrate_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report which tenants would change, without migrating anything",
    )
    migrate_parser.add_argument(
        "--yes",
        action="store_true",
        help=(
            "Skip the confirmation prompt for --all-tenants. Required when "
            "running non-interactively (no TTY, e.g. in CI)"
        ),
    )
    migrate_parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Print a machine-readable JSON summary instead of human-readable lines",
    )

    # -------------------------------------------------
    # db migrate / db status
    # -------------------------------------------------

    db_parser = subparsers.add_parser(
        "db",
        help="Apply or inspect py-authz's Postgres schema migrations",
        description="Apply or inspect the bundled Postgres schema migrations (tenants, "
        "audit logs and the control-plane tables).",
        epilog="Examples:\n  py-authz db status --dsn $POSTGRES_DSN --check\n"
        "  py-authz db migrate --dsn $POSTGRES_DSN\n\n" + _ENV_VARS,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    db_sub = db_parser.add_subparsers(dest="db_command", required=True)
    db_migrate = db_sub.add_parser(
        "migrate",
        help="Apply every pending migration (takes an advisory lock; safe to run concurrently)",
    )
    db_status = db_sub.add_parser("status", help="List migrations and whether each is applied")
    for sub in (db_migrate, db_status):
        sub.add_argument("--dsn", required=False, help="Postgres DSN (env: POSTGRES_DSN)")
        sub.add_argument(
            "--json",
            action="store_true",
            dest="json_output",
            help="Print a machine-readable JSON summary",
        )
    db_migrate.add_argument(
        "--lock-timeout",
        type=float,
        default=300.0,
        help="Seconds to wait for another process's migration lock (default: 300)",
    )
    db_status.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 if any migration is pending (for CI and deploy gates)",
    )

    args = parser.parse_args()

    # `TenantManager`/`MigrationManager` (used by `migrate`) emit progress
    # via the standard `logging` module (`provision_start tenant=...`,
    # `migration_start tenant=...`) — invisible by default since nothing
    # configures a handler. This is the one place in the library that
    # should: it's a CLI process, not a library import into a host app
    # that already owns its own logging configuration.
    setup_logging(level=logging.DEBUG if args.verbose else logging.INFO)

    try:
        if args.command == "generate-model":
            if args.module:
                load_module(args.module)
            generate_command(output=args.output, validate=not args.no_validate)

        elif args.command == "sync":
            if args.module:
                load_module(args.module)
            # `anyio.run(func, *args, backend=..., backend_options=...)`
            # does NOT forward arbitrary keyword arguments to `func` — it
            # only accepts positional `*args`. Passing keyword arguments
            # here raised `TypeError: run() got an unexpected keyword
            # argument` the moment this command was actually run; nothing
            # caught it because the test suite's `anyio.run` stub was
            # more permissive than the real one. A zero-arg
            # `functools.partial` sidesteps the mismatch entirely.
            anyio.run(
                functools.partial(
                    sync_command,
                    store_id=args.store_id,
                    api_url=args.api_url,
                    model_id=args.model_id,
                    force=args.force,
                    json_output=args.json_output,
                )
            )

        elif args.command == "migrate":
            if not args.all_tenants and not args.tenant_ids:
                parser.error("migrate requires --all-tenants or at least one --tenant")
            backend = args.backend or os.environ.get("TENANT_STORE_BACKEND")
            if not backend:
                parser.error(
                    "migrate requires --backend (or TENANT_STORE_BACKEND): postgres, redis, "
                    "or memory (local testing only)"
                )
            if backend not in ("memory", "postgres", "redis"):
                parser.error(f"invalid backend {backend!r}: expected postgres, redis or memory")
            if args.module:
                load_module(args.module)
            anyio.run(
                functools.partial(
                    migrate_command,
                    api_url=args.api_url,
                    backend=backend,
                    allow_empty=args.allow_empty,
                    conn=args.conn,
                    tenant_ids=args.tenant_ids,
                    dry_run=args.dry_run,
                    yes=args.yes,
                    json_output=args.json_output,
                )
            )

        elif args.command == "db":
            if args.db_command == "migrate":
                anyio.run(
                    functools.partial(
                        db_migrate_command,
                        dsn=args.dsn,
                        lock_timeout=args.lock_timeout,
                        json_output=args.json_output,
                    )
                )
            else:
                code = anyio.run(
                    functools.partial(
                        db_status_command,
                        dsn=args.dsn,
                        json_output=args.json_output,
                        check=args.check,
                    )
                )
                if code:
                    raise SystemExit(code)

        else:
            parser.print_help()
    except AuthzError as exc:
        # A known, categorized failure (bad config, an OpenFGA/Keycloak
        # outage, a malformed request) — print a short, friendly message
        # instead of a raw traceback, and exit with a code that lets an
        # automated caller branch on the failure class. Anything that
        # isn't an `AuthzError` (a genuine bug) is deliberately NOT caught
        # here, so it still surfaces its full traceback for debugging.
        logger.debug("CLI command failed", exc_info=exc)
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(_exit_code_for(exc)) from None


if __name__ == "__main__":
    main()

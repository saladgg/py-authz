import argparse
import functools
import logging
import sys
from importlib.metadata import PackageNotFoundError, version

import anyio

from py_authz.cli.commands.generate import generate_command
from py_authz.cli.commands.migrate import migrate_command
from py_authz.cli.commands.sync import sync_command
from py_authz.cli.utils import load_module
from py_authz.core.exceptions import (
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    InvalidAuthzRequest,
    TenantNotFoundError,
)
from py_authz.core.logging import setup_logging

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
    (AuthzError, 1),  # fallback for any other AuthzError subclass
]


def _exit_code_for(exc: AuthzError) -> int:
    for exc_type, code in _EXIT_CODES:
        if isinstance(exc, exc_type):
            return code
    return 1


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
  TENANT_STORE_CONN   Postgres DSN / Redis URL          (migrate --backend postgres|redis)
"""

_EPILOG = f"""\
Examples:
  # Generate the OpenFGA schema from your registered models
  py-authz generate-model --module myapp.authz.models --output model.json

  # Diff + sync to a running OpenFGA instance
  py-authz sync --module myapp.authz.models --api-url http://localhost:8082 --store-id $STORE_ID

  # Roll the current model out to every known tenant, previewing first
  py-authz migrate --module myapp.authz.models --all-tenants --dry-run
  py-authz migrate --module myapp.authz.models --all-tenants --yes

  # Migrate just one tenant, with a machine-readable summary for CI
  py-authz migrate --tenant acme-corp --api-url http://localhost:8082 --json

{_ENV_VARS}
Config precedence: an explicit CLI flag always wins over its matching env
var above (e.g. `--api-url` overrides $FGA_API_URL); a required value
missing from both raises a ConfigurationError (exit code 2).
"""


def main():
    parser = argparse.ArgumentParser(
        prog="py-authz",
        description="CLI tooling for py-authz: generate, sync, and migrate OpenFGA models.",
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
            "  py-authz migrate --module myapp.authz.models --all-tenants --dry-run\n"
            "  py-authz migrate --module myapp.authz.models --all-tenants --yes\n"
            "  py-authz migrate --tenant acme-corp --api-url http://localhost:8082 --json\n\n"
            + _ENV_VARS
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
        default="memory",
        help=(
            "Where tenant->store mappings and model versions are persisted "
            "(default: memory, for local testing only — a fresh in-memory "
            "store has no tenants to find)"
        ),
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
            if args.module:
                load_module(args.module)
            anyio.run(
                functools.partial(
                    migrate_command,
                    api_url=args.api_url,
                    backend=args.backend,
                    conn=args.conn,
                    tenant_ids=args.tenant_ids,
                    dry_run=args.dry_run,
                    yes=args.yes,
                    json_output=args.json_output,
                )
            )

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

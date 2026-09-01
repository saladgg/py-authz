import argparse
import functools
import logging
import sys

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
    (ExternalServiceError, 4),
    (AuthzError, 1),  # fallback for any other AuthzError subclass
]


def _exit_code_for(exc: AuthzError) -> int:
    for exc_type, code in _EXIT_CODES:
        if isinstance(exc, exc_type):
            return code
    return 1


def main():
    parser = argparse.ArgumentParser(prog="py-authz")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable debug-level logging (e.g. tenant provisioning/migration progress)",
    )
    subparsers = parser.add_subparsers(dest="command")

    # -------------------------------------------------
    # generate-model
    # -------------------------------------------------
    gen_parser = subparsers.add_parser("generate-model")
    gen_parser.add_argument(
        "--output",
        "-o",
        help="Output file (default: stdout)",
        default=None,
    )
    gen_parser.add_argument(
        "--module",
        help="Python module path containing authz models",
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

    sync_parser = subparsers.add_parser("sync")

    sync_parser.add_argument("--store-id", required=False)
    sync_parser.add_argument("--api-url", required=False)
    sync_parser.add_argument("--model-id", required=False)
    sync_parser.add_argument(
        "--force",
        action="store_true",
        help="Force upload even if model unchanged",
    )
    sync_parser.add_argument(
        "--module",
        help="Python module path containing authz models",
        required=False,
    )

    # -------------------------------------------------
    # migrate
    # -------------------------------------------------

    migrate_parser = subparsers.add_parser("migrate", help="Roll a model change out across tenants")
    migrate_parser.add_argument("--api-url", required=False)
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
            "Connection string for --backend (Postgres DSN or Redis URL); "
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
        help="Python module path containing authz models",
        required=False,
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

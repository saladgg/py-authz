import argparse

import anyio

from py_authz.cli.commands.generate import generate_command
from py_authz.cli.commands.sync import sync_command
from py_authz.cli.utils import load_module


def main():
    parser = argparse.ArgumentParser(prog="py-authz")
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
    args = parser.parse_args()

    if args.command == "generate-model":
        if args.module:
            load_module(args.module)
        generate_command(output=args.output)

    elif args.command == "sync":
        if args.module:
            load_module(args.module)
        anyio.run(
            sync_command,
            store_id=args.store_id,
            api_url=args.api_url,
            model_id=args.model_id,
            force=args.force,
        )

    else:
        parser.print_help()


if __name__ == "__main__":
    main()

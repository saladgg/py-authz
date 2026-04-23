"""
Bootstrap an OpenFGA store for the examples.

Run once before any example:
    uv run python examples/seed.py

What it does:
    1. Creates a fresh OpenFGA store named "py-authz-examples"
    2. Generates the authorization model from `examples/models.py` and uploads it
    3. Writes a handful of permission tuples so later examples have real data
    4. Prints `FGA_STORE_ID` / `FGA_MODEL_ID` env exports for you to copy

Everything is done through `OpenFGAClient` — no raw HTTP.

"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

# Ensure the project root is importable so `from examples import models` works
# whether the script is run as `python examples/seed.py` or `python -m examples.seed`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples import models  # noqa: E402, F401  — register models via import side-effect
from py_authz.clients.openfga import OpenFGAClient  # noqa: E402
from py_authz.core.model_sync import ModelSync  # noqa: E402

OPENFGA_URL = os.environ.get("FGA_API_URL", "http://localhost:8080")
STORE_NAME = "py-authz-examples"

# Tuples that seed realistic permissions.
# Format: (user, relation, object)
SEED_TUPLES: list[tuple[str, str, str]] = [
    ("user:alice", "owner", "folder:engineering"),
    ("user:bob", "editor", "folder:engineering"),
    ("user:carol", "viewer", "folder:engineering"),
    ("user:alice", "owner", "document:roadmap"),
    ("user:bob", "editor", "document:roadmap"),
    ("user:carol", "viewer", "document:roadmap"),
    ("user:dave", "viewer", "document:public-announcement"),
]


async def main() -> None:
    print(f"Connecting to OpenFGA at {OPENFGA_URL}")

    # Bootstrap: no store yet, so create one via the client.
    bootstrap = OpenFGAClient(api_url=OPENFGA_URL, store_id=None, model_id=None)
    try:
        store_id = await bootstrap.create_store(STORE_NAME)
        print(f"Created store: {store_id}")

        # Reuse the same client for model sync + tuple writes.
        bootstrap.store_id = store_id

        syncer = ModelSync(bootstrap)
        model_id = await syncer.sync(force=True)
        print(f"Synced model: {model_id}")

        await bootstrap.write_tuples(
            writes=[{"user": u, "relation": r, "object": o} for u, r, o in SEED_TUPLES]
        )
        print(f"Wrote {len(SEED_TUPLES)} tuples")
    finally:
        await bootstrap.aclose()

    print("\nExport these for the other examples:")
    print(f"  export FGA_API_URL={OPENFGA_URL}")
    print(f"  export FGA_STORE_ID={store_id}")
    print(f"  export FGA_MODEL_ID={model_id}")


if __name__ == "__main__":
    asyncio.run(main())

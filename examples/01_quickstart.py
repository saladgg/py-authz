"""

01 — Quickstart: a single authorization check.

The smallest useful program: wire an `OpenFGAClient` + `AuthzEngine` behind
the high-level `Authz` facade, then ask "is this user allowed to do X on Y?"

Prereq: run `examples/seed.py` first and export FGA_STORE_ID / FGA_MODEL_ID.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


from py_authz import Authz, Identity, Resource
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


async def main() -> None:
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    engine = AuthzEngine(fga_client=client)
    authz = Authz(engine)

    alice = Identity(id="user:alice")
    carol = Identity(id="user:carol")
    roadmap = Resource(type="document", id="roadmap")

    try:
        # alice owns the roadmap, so she can edit it (owner → editor via union)
        print("alice can edit roadmap:", await authz.enforce("editor", alice, roadmap))

        # carol is only a viewer — editing should be denied
        print("carol can edit roadmap:", await authz.enforce("editor", carol, roadmap))

        # .require() raises AuthorizationDenied on failure; good for service code
        # where denial should short-circuit execution.
        await authz.require("viewer", carol, roadmap)
        print("carol.require('viewer') passed")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

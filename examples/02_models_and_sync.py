"""
02 — ResourceModels, typed checks, and model sync.

Two things this demonstrates:

1. Defining authorization in Python with `ResourceModel` + `Relation`, then
   generating the OpenFGA schema from it — no hand-written JSON.

2. Syncing the generated model to OpenFGA. `ModelSync.sync()` diffs the local
   model against whatever is already uploaded, so it's idempotent and cheap
   to run on every deploy.

Once synced, you can use `Authz.can(Document.view, user, doc)` with the
typed relation object instead of string literals.
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


from examples.models import Document
from py_authz import Authz, Identity
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from py_authz.modeling.generator import generate_model


async def main() -> None:
    # 1) Inspect the generated model (no OpenFGA call yet)
    print("Generated OpenFGA model:")
    print(json.dumps(generate_model(), indent=2))

    # 2) Sync it. Idempotent: returns the existing model_id if nothing changed.
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=None,
    )
    engine = AuthzEngine(fga_client=client)
    authz = Authz(engine)

    try:
        model_id = await authz.sync_model()
        print(f"\nActive model: {model_id}")

        # 3) Check using the typed Relation object. `authz.can(...)` accepts
        #    either a string ("viewer") or a Relation (Document.viewer). With
        #    the Relation form, you pass the ResourceModel instance directly.
        alice = Identity(id="user:alice")
        roadmap = Document(id="roadmap")

        print("alice can view roadmap:", await authz.can(Document.viewer, alice, roadmap))
        print("alice can edit roadmap:", await authz.can(Document.editor, alice, roadmap))
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

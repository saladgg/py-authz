"""
08 — List objects: the inverse query.

`enforce` answers "can this user do X on object Y?". List views need the
inverse: "which Ys can this user do X on?". Looping `enforce` per row is
O(n) round-trips; `list_objects` is one call.

Use it for inboxes, file explorers, admin tables — anywhere you'd otherwise
filter the page after fetching it.

Prereq: run `examples/seed.py` first and export FGA_* env vars.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.models import Document
from py_authz import Authz, Identity
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
    dave = Identity(id="user:dave")

    try:
        # Seed a couple of extra documents so the result is more interesting.
        # In a real app these tuples come from your provisioning flow, not the
        # request path. `grant` takes a `Resource`, so call `.to_resource()`.
        await authz.grant(alice, "viewer", Document(id="design").to_resource())
        await authz.grant(alice, "editor", Document(id="okrs").to_resource())

        # Typed form: pass the Relation off the ResourceModel — type is derived.
        # Returns "<type>:<id>" strings exactly as OpenFGA reports them.
        alice_viewable = await authz.list_objects(Document.viewer, alice)
        print(f"alice can view: {alice_viewable}")

        # String form: must pass `resource_type` explicitly.
        dave_viewable = await authz.list_objects("viewer", dave, "document")
        print(f"dave  can view: {dave_viewable}")

        # `editor` is a narrower relation — only the docs alice can actually edit.
        alice_editable = await authz.list_objects(Document.editor, alice)
        print(f"alice can edit: {alice_editable}")
    finally:
        # Clean up the docs we created so re-runs are idempotent.
        await authz.revoke(alice, "viewer", Document(id="design").to_resource())
        await authz.revoke(alice, "editor", Document(id="okrs").to_resource())
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

"""
11 — Hierarchical permissions: a folder viewer is a document viewer too.

`Document.viewer` is declared with `from_parent=("parent", "viewer")`
(see `examples/models.py`) — OpenFGA's `tupleToUserset` rewrite. This is
the mechanism for "permission inherited from a *different*, parent
object", distinct from `union`/`inherits` (which only ever combine
relations on the *same* object).

`document:budget` (seeded by `seed.py`) has a `parent` tuple pointing at
`folder:engineering` and NO direct grants of its own. carol — a viewer of
that folder — can view it purely through that inheritance; dave, who has
no relationship to the folder at all, cannot.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.models import Document, Folder
from py_authz import Authz, Identity
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


async def main() -> None:
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    authz = Authz(AuthzEngine(fga_client=client))

    try:
        carol = Identity(id="user:carol")
        dave = Identity(id="user:dave")
        budget = Document(id="budget")

        print(
            "carol is a viewer of folder:engineering:",
            await authz.enforce("viewer", carol, Folder(id="engineering").to_resource()),
        )
        print(
            "carol can view document:budget (inherited, no direct grant):",
            await authz.can(Document.viewer, carol, budget),
        )
        print(
            "dave can view document:budget (no relationship to the folder):",
            await authz.can(Document.viewer, dave, budget),
        )
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

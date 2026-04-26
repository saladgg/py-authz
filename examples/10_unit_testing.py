"""
10 — Unit-testing authz code without OpenFGA.

`make_fake_authz()` builds an `Authz` instance backed by an in-memory store.
Use it in unit tests so CI doesn't need to boot OpenFGA. The fake honors:

    - direct (user, relation, object) tuples written via `grant` / `revoke`
    - union edges declared on registered `ResourceModel` classes
      (e.g. `editor = Relation("editor", union=["owner"])`)
    - per-request `contextual_tuples` on `enforce` / `can` / `list_objects`

It does NOT implement OpenFGA conditions, tuple-to-userset rewrites beyond
simple unions, or wildcard subjects. For those, run a real OpenFGA in CI.
The fake covers the RBAC patterns that dominate unit-test surface area.

Run: `uv run python examples/10_unit_testing.py`
No OpenFGA needed — no env vars, no docker.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples import models  # noqa: F401 — register Document/Folder
from examples.models import Document
from py_authz import ContextualTuple, Identity
from py_authz.testkit import make_fake_authz


async def main() -> None:
    authz = make_fake_authz()

    alice = Identity(id="user:alice")
    bob = Identity(id="user:bob")
    roadmap = Document(id="roadmap")
    design = Document(id="design")

    # 1) grant + check round-trips through the in-memory store.
    #    `grant` takes a `Resource`, so call `.to_resource()` on the model.
    await authz.grant(alice, "owner", roadmap.to_resource())
    await authz.grant(bob, "viewer", design.to_resource())

    # 2) Union edges resolve transitively: owner → editor → viewer.
    print("alice owner roadmap?  ", await authz.can(Document.owner, alice, roadmap))
    print("alice editor roadmap? ", await authz.can(Document.editor, alice, roadmap))
    print("alice viewer roadmap? ", await authz.can(Document.viewer, alice, roadmap))

    # 3) list_objects works against the fake too.
    print("alice can view:", await authz.list_objects(Document.viewer, alice))
    print("bob   can view:", await authz.list_objects(Document.viewer, bob))

    # 4) Contextual tuples are honored without persisting.
    secret = Document(id="secret")
    allowed = await authz.enforce(
        "viewer",
        alice,
        secret.to_resource(),
        contextual_tuples=[
            ContextualTuple("user:alice", "owner", "document:secret"),
        ],
    )
    print(f"alice viewer secret (with ctx tuple): {allowed}")
    print(
        "alice viewer secret (without):       ",
        await authz.can(Document.viewer, alice, secret),
    )

    # 5) revoke drops the tuple.
    await authz.revoke(alice, "owner", roadmap.to_resource())
    print("after revoke — alice owner roadmap?", await authz.can(Document.owner, alice, roadmap))


# In real tests you'd skip `main` and write pytest cases like:
#
#     @pytest.mark.asyncio
#     async def test_only_owner_can_edit():
#         authz = make_fake_authz()
#         alice = Identity(id="user:alice")
#         doc = Document(id="x")
#         await authz.grant(alice, "owner", doc.to_resource())
#         assert await authz.can(Document.editor, alice, doc) is True


if __name__ == "__main__":
    asyncio.run(main())

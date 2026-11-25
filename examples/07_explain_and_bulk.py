"""
07 — Explain decisions, enforce in bulk, manage tuples.

Three newer APIs exposed on `AuthzEngine` and `Authz` that are easy to miss:

    - `engine.explain(request)` returns an `AuthzExplanation` — allowed, a
      human-readable reason and, when allowed, the relation `path` that
      grants access (walked from OpenFGA `/expand`). Handy for debugging
      permissions in production.

    - `engine.bulk_enforce(requests)` checks N requests concurrently (bounded
      by `concurrency=`). Useful for list views where you need to know which
      items in a page the user can act on.

    - `authz.grant / revoke / grant_many / revoke_many` write and delete
      tuples through the high-level API — no more dropping down to the
      OpenFGA HTTP API for permission changes.

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
from py_authz.core.types import AuthzRequest, Resource


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
        # 1) Explain — same shape as enforce, but returns why.
        allowed = await engine.explain(
            AuthzRequest(identity=carol, action="editor", resource=roadmap)
        )
        print(f"carol can edit roadmap: {allowed.allowed}  — {allowed.reason}")
        if allowed.path:
            print(f"  via: {' -> '.join(allowed.path)}")

        # 2) Bulk enforce — fan out to OpenFGA with bounded concurrency.
        requests = [
            AuthzRequest(identity=alice, action="viewer", resource=roadmap),
            AuthzRequest(identity=alice, action="editor", resource=roadmap),
            AuthzRequest(identity=carol, action="viewer", resource=roadmap),
            AuthzRequest(identity=carol, action="editor", resource=roadmap),
        ]
        results = await engine.bulk_enforce(requests, concurrency=4)
        for r in results:
            print(
                f"  {r.request.identity.id:12} {r.request.action:7} "
                f"{r.request.resource.to_fga_object():20} → {r.allowed}"
            )

        # 3) Grant / revoke — manage tuples without touching the HTTP API.
        #    `grant` takes a ResourceModel or Resource (anything with
        #    `.to_fga_object()`). `revoke` undoes it.
        scratch = Document(id="scratch")
        await authz.grant(carol, "editor", scratch)
        after_grant = await authz.can(Document.editor, carol, scratch)
        print(f"after grant  — carol editor scratch: {after_grant}")

        await authz.revoke(carol, "editor", scratch)
        after_revoke = await authz.can(Document.editor, carol, scratch)
        print(f"after revoke — carol editor scratch: {after_revoke}")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

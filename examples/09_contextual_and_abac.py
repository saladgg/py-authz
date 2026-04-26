"""
09 — Contextual tuples and ABAC context.

Two per-request hooks let you go beyond pure RBAC without writing tuples:

    - `contextual_tuples` — relationship tuples that participate in this
      check only and are NOT persisted. Useful for "what-if" simulations,
      one-shot delegations, or modeling state that lives outside FGA
      (e.g. "the caller is currently impersonating this user").

    - `context` — a dict forwarded to OpenFGA condition expressions. This
      is the ABAC bridge: time-bounded grants, IP allowlists, "only during
      business hours". Requires conditions declared in your authorization
      model — the bare RBAC model in `examples/models.py` doesn't use
      them, so this example only shows the wiring; see the OpenFGA docs
      on conditions to make it bite.

Both bypass the cache: per-request inputs make decisions non-deterministic
from the (user, relation, object) key alone.

Prereq: run `examples/seed.py` first and export FGA_* env vars.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.models import Document
from py_authz import Authz, ContextualTuple, Identity
from py_authz.cache.memory import InMemoryCache
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


async def main() -> None:
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],
        store_id=os.environ["FGA_STORE_ID"],
        model_id=os.environ["FGA_MODEL_ID"],
    )
    engine = AuthzEngine(fga_client=client, cache=InMemoryCache())
    authz = Authz(engine)

    alice = Identity(id="user:alice")
    scratch = Document(id="scratch")  # nobody has any tuple on this doc

    try:
        # 1) Baseline — alice has no relation on `scratch`, so this is False.
        baseline = await authz.can(Document.viewer, alice, scratch)
        print(f"baseline: alice can view scratch? {baseline}")

        # 2) Contextual tuple — pretend, just for this request, that alice is
        #    the owner. `viewer` resolves through the union edge, so the check
        #    succeeds. Nothing is written to OpenFGA.
        what_if = await authz.enforce(
            "viewer",
            alice,
            scratch.to_resource(),
            contextual_tuples=[
                ContextualTuple(
                    user="user:alice",
                    relation="owner",
                    object="document:scratch",
                ),
            ],
        )
        print(f"with ctx tuple: alice can view scratch? {what_if}")

        # 3) Persisted state is unchanged.
        after = await authz.can(Document.viewer, alice, scratch)
        print(f"after (no leak): alice can view scratch? {after}")

        # 4) ABAC context — forwarded to FGA conditions verbatim. With a
        #    bare RBAC model this is a no-op; the call demonstrates the
        #    surface, not the evaluation. Requests carrying context skip
        #    the cache, so this always re-checks FGA.
        roadmap = Document(id="roadmap")
        await authz.enforce(
            "viewer",
            alice,
            roadmap.to_resource(),
            context={
                "current_time": "2026-04-26T14:00:00Z",
                "ip": "10.0.0.1",
            },
        )
        print("context-bearing check completed (cache bypassed)")
    finally:
        await client.aclose()


if __name__ == "__main__":
    asyncio.run(main())

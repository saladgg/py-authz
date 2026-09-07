"""
Structural (`Protocol`) types describing what `AuthzEngine` actually needs
from an FGA client, decoupled from any concrete implementation.

Extracted so `AuthzEngine` can be typed against the *shape* it uses
(`check`/`list_objects`/`write_tuples`/`store_id`) rather than the concrete
`OpenFGAClient` class — the latter made `testkit.InMemoryFGAClient` (which
implements the same shape but doesn't inherit from `OpenFGAClient`) a real
mypy `arg-type` error on the library's own official test helper, invisible
only because mypy's `arg-type` check was globally disabled (see DX2-2).
`explain`/`aclose` are deliberately NOT part of this protocol: both are
optional, duck-typed via `hasattr`/`getattr` at their call sites, so no
static contract is needed for them.
"""

from typing import Protocol


class FGAClientProtocol(Protocol):
    store_id: str | None

    async def check(
        self,
        user: str,
        relation: str,
        object: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,
    ) -> bool: ...

    async def list_objects(
        self,
        user: str,
        relation: str,
        type: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,
    ) -> list[str]: ...

    async def write_tuples(
        self,
        writes: list[dict],
        deletes: list[dict] | None = None,
    ) -> None: ...

    async def read_tuples(
        self,
        *,
        user: str | None = None,
        relation: str | None = None,
        object: str | None = None,
        page_size: int | None = None,
        continuation_token: str | None = None,
    ) -> dict: ...

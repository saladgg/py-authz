"""
Turn OpenFGA `/expand` trees into a human-readable access path (ARCH3-8).

`/expand` returns one level of a relation's userset tree: direct users,
plus references (`computed`, `tupleToUserset`, usersets like
`team:x#member`) that need expanding in turn. `find_path` walks those
references breadth-first-ish (depth-first with a call budget) until it
finds the user, and returns the chain of usersets it went through, e.g.::

    ["document:roadmap#viewer", "document:roadmap#editor",
     "folder:eng#editor", "user:alice"]

Limits worth knowing:

- `/expand` does not evaluate conditions, so for a model using them the
  path is the route the tuples allow, which the condition then gated.
  `AuthzEngine.explain()` reports `allowed` from a real `/check`, so the
  decision itself is always right.
- The walk is bounded (`max_depth`, `max_calls`). On a very wide or deep
  graph it gives up and returns `None` rather than hammering OpenFGA.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

ExpandFn = Callable[[str, str], Awaitable[dict[str, Any] | None]]


class _Budget:
    def __init__(self, max_calls: int):
        self.remaining = max_calls


async def find_path(
    expand: ExpandFn,
    user: str,
    relation: str,
    object: str,
    *,
    max_depth: int = 8,
    max_calls: int = 50,
) -> list[str] | None:
    """
    Return the chain of usersets through which `user` holds `relation` on
    `object`, ending with the matched user (or wildcard / userset entry),
    or `None` if no path was found within the limits.

    `expand(relation, object)` must return the `/expand` response's
    `tree.root` node (or `None`).
    """
    budget = _Budget(max_calls)
    return await _expand_userset(expand, user, f"{object}#{relation}", 0, max_depth, budget, set())


async def _expand_userset(
    expand: ExpandFn,
    user: str,
    userset: str,
    depth: int,
    max_depth: int,
    budget: _Budget,
    seen: set[str],
) -> list[str] | None:
    if depth > max_depth or budget.remaining <= 0 or userset in seen:
        return None
    obj, _, relation = userset.rpartition("#")
    if not obj or not relation:
        return None
    budget.remaining -= 1
    root = await expand(relation, obj)
    if not root:
        return None
    sub = await _walk(expand, user, root, depth, max_depth, budget, seen | {userset})
    return None if sub is None else [userset, *sub]


async def _walk(
    expand: ExpandFn,
    user: str,
    node: dict[str, Any],
    depth: int,
    max_depth: int,
    budget: _Budget,
    seen: set[str],
) -> list[str] | None:
    if "leaf" in node:
        return await _walk_leaf(expand, user, node["leaf"], depth, max_depth, budget, seen)

    if "union" in node:
        for child in node["union"].get("nodes", []):
            found = await _walk(expand, user, child, depth, max_depth, budget, seen)
            if found is not None:
                return found
        return None

    if "intersection" in node:
        # Every branch must hold; report the first branch's route (the
        # others are required too, and `/check` already confirmed them).
        paths = []
        for child in node["intersection"].get("nodes", []):
            found = await _walk(expand, user, child, depth, max_depth, budget, seen)
            if found is None:
                return None
            paths.append(found)
        return paths[0] if paths else None

    if "difference" in node:
        # The base grants access; the subtract side is what `/check`
        # already confirmed doesn't apply.
        base = node["difference"].get("base")
        return await _walk(expand, user, base, depth, max_depth, budget, seen) if base else None

    return None


async def _walk_leaf(
    expand: ExpandFn,
    user: str,
    leaf: dict[str, Any],
    depth: int,
    max_depth: int,
    budget: _Budget,
    seen: set[str],
) -> list[str] | None:
    user_type = user.partition(":")[0]

    if "users" in leaf:
        entries = leaf["users"].get("users", []) or []
        if user in entries:
            return [user]
        if f"{user_type}:*" in entries:
            return [f"{user_type}:*"]
        for entry in entries:
            if "#" in entry:
                found = await _expand_userset(
                    expand, user, entry, depth + 1, max_depth, budget, seen
                )
                if found is not None:
                    return found
        return None

    if "computed" in leaf:
        userset = leaf["computed"].get("userset")
        if userset:
            return await _expand_userset(expand, user, userset, depth + 1, max_depth, budget, seen)
        return None

    if "tupleToUserset" in leaf:
        for computed in leaf["tupleToUserset"].get("computed", []) or []:
            userset = computed.get("userset")
            if not userset:
                continue
            found = await _expand_userset(expand, user, userset, depth + 1, max_depth, budget, seen)
            if found is not None:
                return found
        return None

    return None

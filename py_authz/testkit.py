"""
Test helpers for py-authz consumers.

Lets users unit-test authz code without booting OpenFGA. The fake honors:
    - direct (user, relation, object) tuples written via grant/revoke
    - union/inherits edges declared on registered ResourceModel classes
      (e.g. ``editor = Relation("editor", union=["owner"])`` — ``inherits``
      is accepted identically, matching the real generator: see
      ``modeling/base.py``'s ``Relation`` docstring)
    - parent-relation inheritance declared via ``Relation(from_parent=...)``
      (e.g. ``viewer = Relation("viewer", from_parent=("parent", "viewer"))``),
      including multiple parent relations ORed together
      (``from_parent=[("parent_a", "viewer"), ("parent_b", "viewer")]``)
    - intersections (``Relation(intersection=["editor", "verified"])``)
    - exclusions (``Relation(exclude="banned")``)
    - per-request contextual tuples on check / list_objects

It does NOT implement the full OpenFGA evaluation engine (no conditions/ABAC,
no nested intersection/difference beyond one level). For anything more
elaborate, spin up a real OpenFGA instance — this fake covers the common
RBAC (+ hierarchy/intersection/exclusion) patterns that dominate unit-test
surface area.
"""

from __future__ import annotations

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.modeling.base import Relation, ResourceModel, from_parent_pairs
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.modeling.registry import registry as default_registry


class InMemoryFGAClient:
    """
    Drop-in replacement for ``OpenFGAClient`` backed by an in-memory set.

    Intended for unit tests. Implements the subset of the client surface
    that ``AuthzEngine`` and ``Authz`` exercise: ``check``, ``list_objects``,
    ``write_tuples``, ``aclose``.
    """

    def __init__(
        self,
        *,
        store_id: str = "in-memory",
        model_id: str | None = "in-memory-model",
        model_registry: ResourceModelRegistry | None = None,
    ):
        # Widened to `str | None` (never actually `None` here, since
        # `store_id`'s own parameter default is `"in-memory"`) to
        # structurally match `FGAClientProtocol.store_id` — a `Protocol`
        # attribute's type must match invariantly, not just be a subtype
        # (see DX2-2).
        self.store_id: str | None = store_id
        self.model_id = model_id
        self._registry = model_registry or default_registry
        self._tuples: set[tuple[str, str, str]] = set()

    # ------------------------------------------------------------------
    # Tuple management
    # ------------------------------------------------------------------

    async def write_tuples(
        self,
        writes: list[dict],
        deletes: list[dict] | None = None,
    ) -> None:
        for t in writes or []:
            self._tuples.add((t["user"], t["relation"], t["object"]))
        for t in deletes or []:
            self._tuples.discard((t["user"], t["relation"], t["object"]))

    async def read_tuples(
        self,
        *,
        user: str | None = None,
        relation: str | None = None,
        object: str | None = None,
        page_size: int | None = None,  # noqa: ARG002 — accepted for parity, no real paging
        continuation_token: str | None = None,  # noqa: ARG002 — ditto
    ) -> dict:
        """See `OpenFGAClient.read_tuples()` — same filter/return shape,
        minus real pagination (this fake never has enough tuples for it
        to matter)."""
        matches = [
            {"user": u, "relation": r, "object": o, "timestamp": None}
            for (u, r, o) in sorted(self._tuples)
            if (user is None or u == user)
            and (relation is None or r == relation)
            and (object is None or o == object)
        ]
        return {"tuples": matches, "continuation_token": None}

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    async def check(
        self,
        user: str,
        relation: str,
        object: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,  # noqa: ARG002 — accepted for parity
    ) -> bool:
        extra = {(t["user"], t["relation"], t["object"]) for t in (contextual_tuples or [])}
        return self._check(user, relation, object, extra)

    async def list_objects(
        self,
        user: str,
        relation: str,
        type: str,
        *,
        contextual_tuples: list[dict] | None = None,
        context: dict | None = None,  # noqa: ARG002 — accepted for parity
    ) -> list[str]:
        extra = {(t["user"], t["relation"], t["object"]) for t in (contextual_tuples or [])}

        prefix = f"{type}:"
        candidates = {obj for _u, _r, obj in self._tuples | extra if obj.startswith(prefix)}

        return sorted(o for o in candidates if self._check(user, relation, o, extra))

    async def aclose(self) -> None:
        return None

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check(
        self,
        user: str,
        relation: str,
        obj: str,
        extra: set[tuple[str, str, str]],
        seen: set[tuple[str, str, str]] | None = None,
    ) -> bool:
        seen = seen or set()
        key = (user, relation, obj)
        if key in seen:
            return False
        seen.add(key)

        obj_type = obj.split(":", 1)[0]
        model = self._lookup_model(obj_type)
        rel = self._lookup_relation(model, relation) if model is not None else None

        base_holds = self._base_holds(user, relation, obj, extra, seen, key, rel)

        if not base_holds:
            return False

        # Exclusion (OpenFGA `difference`): even if the base relation-def
        # holds, `exclude` revokes it — mirrors
        # `OpenFGAModelGenerator._build_relation()`'s `difference` rewrite,
        # which wraps the *entire* base, not just one branch of it.
        return not (
            rel is not None and rel.exclude and self._check(user, rel.exclude, obj, extra, seen)
        )

    def _base_holds(
        self,
        user: str,
        relation: str,
        obj: str,
        extra: set[tuple[str, str, str]],
        seen: set[tuple[str, str, str]],
        key: tuple[str, str, str],
        rel: Relation | None,
    ) -> bool:
        if key in self._tuples or key in extra:
            return True

        if rel is None:
            return False

        # Walk union/inherits edges from the model registry: if `relation`
        # is the union of {a, b}, holding any of those on `obj` implies
        # `relation`. `inherits` is walked identically to `union` — the
        # real generator (`modeling/generator.py`) compiles both to the
        # exact same `computedUserset` rewrite, so the fake must too, or
        # a model using `inherits=` would behave correctly against real
        # OpenFGA but incorrectly (falsely denied) here.
        same_object_parents = (*rel.union, *rel.inherits)
        if any(self._check(user, parent, obj, extra, seen) for parent in same_object_parents):
            return True

        # Intersection (AND of named same-object relations): holds only
        # if every named relation holds.
        if rel.intersection and all(
            self._check(user, name, obj, extra, seen) for name in rel.intersection
        ):
            return True

        # Walk parent-relation inheritance (tupleToUserset): if `obj`'s
        # `tupleset_relation` points at some parent object(s), the user
        # holds `relation` on `obj` if they hold `computed_relation` on
        # any of those parents. One or many `(tupleset_relation,
        # computed_relation)` pairs, ORed together.
        all_tuples = self._tuples | extra
        for tupleset_relation, computed_relation in from_parent_pairs(rel.from_parent):
            parents = {u for u, r, o in all_tuples if r == tupleset_relation and o == obj}
            if any(self._check(user, computed_relation, parent, extra, seen) for parent in parents):
                return True

        return False

    def _lookup_model(self, type_name: str) -> type[ResourceModel] | None:
        try:
            return self._registry.get(type_name)
        except KeyError:
            return None

    def _lookup_relation(self, model: type[ResourceModel], name: str) -> Relation | None:
        attr = getattr(model, name, None)
        return attr if isinstance(attr, Relation) else None


def make_fake_authz(
    *,
    store_id: str = "in-memory",
    model_registry: ResourceModelRegistry | None = None,
) -> Authz:
    """
    Build an ``Authz`` instance backed by an in-memory FGA client.

    Example:
        authz = make_fake_authz()
        await authz.grant(alice, "owner", Document(id="roadmap"))
        assert await authz.can(Document.viewer, alice, Document(id="roadmap"))
    """
    client = InMemoryFGAClient(store_id=store_id, model_registry=model_registry)
    engine = AuthzEngine(fga_client=client)
    return Authz(engine)

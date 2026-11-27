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

``strict=True`` additionally rejects what a real OpenFGA server rejects
(ARCH3-9), raising ``UpstreamRequestRejected`` just like ``OpenFGAClient``
does on a 400: writes or checks naming a type or relation the model
doesn't define, a tuple whose user type isn't an allowed subject of that
relation, duplicate writes, and deletes of tuples that don't exist. The
default (non-strict) mode stays permissive for backwards compatibility,
but strict mode is what caught — after the fact — that the control
plane's service-account principals used a subject type its own RBAC
model never declared (SEC3-3). Prefer it in new tests.

It does NOT implement the full OpenFGA evaluation engine (no conditions/ABAC,
no nested intersection/difference beyond one level). For anything more
elaborate, spin up a real OpenFGA instance — this fake covers the common
RBAC (+ hierarchy/intersection/exclusion) patterns that dominate unit-test
surface area.
"""

from __future__ import annotations

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import UpstreamRequestRejected
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
        strict: bool = False,
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
        self.strict = strict

    # ------------------------------------------------------------------
    # Tuple management
    # ------------------------------------------------------------------

    async def write_tuples(
        self,
        writes: list[dict],
        deletes: list[dict] | None = None,
    ) -> None:
        if self.strict:
            # Validate the whole batch before applying any of it — a real
            # OpenFGA Write is atomic, so a rejected batch changes nothing.
            pending = set(self._tuples)
            for t in writes or []:
                key = (t["user"], t["relation"], t["object"])
                self._validate_tuple(*key)
                if key in pending:
                    self._reject(f"cannot write a tuple which already exists: {key}")
                pending.add(key)
            for t in deletes or []:
                key = (t["user"], t["relation"], t["object"])
                if key not in pending:
                    self._reject(f"cannot delete a tuple which does not exist: {key}")
                pending.discard(key)

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

        # OpenFGA's Read accepts a bare type (`"tenant:"`) as `object`,
        # meaning "every object of that type" — mirrored here so code
        # relying on that (e.g. enumerating a principal's role grants)
        # behaves the same against the fake as against a real server.
        def _object_matches(o: str) -> bool:
            if object is None:
                return True
            if object.endswith(":"):
                return o.startswith(object)
            return o == object

        matches = [
            {"user": u, "relation": r, "object": o, "timestamp": None}
            for (u, r, o) in sorted(self._tuples)
            if (user is None or u == user)
            and (relation is None or r == relation)
            and _object_matches(o)
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
        if self.strict:
            self._validate_query(user, relation, object.split(":", 1)[0])
            for t in contextual_tuples or []:
                self._validate_tuple(t["user"], t["relation"], t["object"])
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
        if self.strict:
            self._validate_query(user, relation, type)
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

        # A `type:*` wildcard tuple grants the relation to every user of
        # that type, as in real OpenFGA (a userset subject never matches).
        user_type, sep, user_id = user.partition(":")
        if sep and user_id != "*" and "#" not in user_id:
            wildcard = (f"{user_type}:*", relation, obj)
            if wildcard in self._tuples or wildcard in extra:
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
        """Find a relation by its OpenFGA name (`Relation.name`), not its
        Python attribute name (ARCH3-9): `view = Relation("viewer", ...)`
        defines the relation `viewer`, exactly as the real generator
        (which keys on `Relation.name`) compiles it. Looking up by
        attribute name made `can("viewer", ...)` silently return False
        here while a real OpenFGA returned True."""
        # `ResourceModelMeta` copies inherited relations into each
        # subclass's own namespace, so the class itself is enough.
        for value in vars(model).values():
            if isinstance(value, Relation) and value.name == name:
                return value
        return None

    # ------------------------------------------------------------------
    # Strict-mode validation (mirrors OpenFGA's own 400s)
    # ------------------------------------------------------------------

    @staticmethod
    def _reject(message: str) -> None:
        raise UpstreamRequestRejected(
            f"OpenFGA rejected the request: {message}", status_code=400, detail=message
        )

    def _known_types(self) -> set[str]:
        # The generator always emits a `user` type alongside every
        # registered model (see `OpenFGAModelGenerator.generate()`).
        return {"user", *(m.type for m in self._registry.all())}

    def _require_relation(self, type_name: str, relation: str) -> Relation:
        model = self._lookup_model(type_name)
        if model is None:
            self._reject(f"type {type_name!r} not found in the authorization model")
        assert model is not None  # noqa: S101 — narrowed by _reject raising
        rel = self._lookup_relation(model, relation)
        if rel is None:
            self._reject(f"relation {type_name}#{relation} not found in the authorization model")
        assert rel is not None  # noqa: S101 — narrowed by _reject raising
        return rel

    def _validate_user(self, user: str) -> None:
        user_type, sep, _ = user.partition(":")
        if not sep:
            self._reject(f"user {user!r} must be of the form 'type:id'")
        if user_type not in self._known_types():
            self._reject(f"type {user_type!r} not found in the authorization model")

    def _validate_query(self, user: str, relation: str, object_type: str) -> None:
        self._validate_user(user)
        self._require_relation(object_type, relation)

    def _validate_tuple(self, user: str, relation: str, obj: str) -> None:
        self._validate_user(user)
        rel = self._require_relation(obj.split(":", 1)[0], relation)

        user_type, _, user_id = user.partition(":")
        if user_id == "*":
            form = f"{user_type}:*"
        elif "#" in user_id:
            form = f"{user_type}#{user_id.split('#', 1)[1]}"
        else:
            form = user_type

        # Tupleset relations named by `from_parent` (e.g. `parent`) accept
        # whatever subject types they declare, same as any other relation.
        if form not in rel.subjects:
            self._reject(
                f"type {form!r} is not an allowed subject of {obj.split(':', 1)[0]}#{relation} "
                f"(allowed: {rel.subjects})"
            )


def make_fake_authz(
    *,
    store_id: str = "in-memory",
    model_registry: ResourceModelRegistry | None = None,
    strict: bool = False,
) -> Authz:
    """
    Build an ``Authz`` instance backed by an in-memory FGA client.

    Example:
        authz = make_fake_authz()
        await authz.grant(alice, "owner", Document(id="roadmap"))
        assert await authz.can(Document.viewer, alice, Document(id="roadmap"))
    """
    client = InMemoryFGAClient(store_id=store_id, model_registry=model_registry, strict=strict)
    engine = AuthzEngine(fga_client=client)
    return Authz(engine)

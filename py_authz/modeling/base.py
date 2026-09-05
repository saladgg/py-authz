from __future__ import annotations


def from_parent_pairs(
    from_parent: tuple[str, str] | list[tuple[str, str]] | None,
) -> list[tuple[str, str]]:
    """
    Normalize `Relation.from_parent` to a list of `(tupleset_relation,
    computed_relation)` pairs, regardless of whether it was declared as a
    single tuple (the original, still-supported shape), a list of tuples
    (multiple parent relations, ORed together — see `Relation.__init__`'s
    `from_parent` docstring), or left as `None`.

    Shared by `OpenFGAModelGenerator._build_relation()` (real generator)
    and `py_authz.testkit.InMemoryFGAClient` (the in-memory fake) so both
    walk exactly the same set of parent-relation pairs.
    """
    if from_parent is None:
        return []
    if isinstance(from_parent, tuple):
        return [from_parent]
    return list(from_parent)


class Relation:
    """
    Represents a relation in the authorization model.

    Supports:
        - direct relations
        - unions (by relation name)
        - computed usersets (inherits — currently an alias of `union`; see
          `union`'s docstring below)
        - subject types
        - parent-relation inheritance (`from_parent`) — e.g. "a viewer of
          the parent folder is a viewer of this document" — one or
          multiple parent relations, ORed together
        - intersections (`intersection`) — e.g. "editor AND verified"
        - exclusions (`exclude`) — e.g. "viewer EXCLUDE banned"
    """

    def __init__(
        self,
        name: str,
        *,
        union: list[str] | None = None,
        inherits: list[str] | None = None,
        subjects: list[str] | None = None,
        from_parent: tuple[str, str] | list[tuple[str, str]] | None = None,
        intersection: list[str] | None = None,
        exclude: str | None = None,
    ):
        """
        Args:
            name (str):
                The relation's name (e.g. "viewer").

            union (Optional[list[str]]):
                Other relation names on the *same object* that also imply
                this one (OpenFGA `computedUserset`) — e.g.
                `union=["editor"]` means "an editor is also a viewer".

            inherits (Optional[list[str]]):
                Currently an alias of `union` — both compile to the exact
                same `computedUserset` rewrite. Kept as a separate,
                same-shaped parameter for backward compatibility with
                existing models; if you're modeling "inherit permissions
                from a *different*, parent object" (e.g. a document
                inheriting a folder's `viewer`), that's `from_parent`,
                not `inherits` — same-object union and cross-object
                parent inheritance are different OpenFGA mechanisms
                (`computedUserset` vs. `tupleToUserset`) and `inherits`
                only ever produced the former.

            subjects (Optional[list[str]]):
                Subject types allowed to hold this relation directly
                (OpenFGA `this` + `directly_related_user_types`).
                Defaults to `["user"]` — UNLESS `from_parent` is set and
                `subjects` isn't explicitly given, in which case it
                defaults to `[]` (see `from_parent`).

            from_parent (Optional[tuple[str, str] | list[tuple[str, str]]]):
                `(tupleset_relation, computed_relation)` — grants this
                relation via OpenFGA's `tupleToUserset`: "for the object
                pointed to by this object's `tupleset_relation` relation,
                does the user hold `computed_relation` on it?". Example:
                `Relation("viewer", from_parent=("parent", "viewer"))` on
                `Document` means "the user is a document viewer if
                they're a viewer of the document's `parent` (a folder)".
                Requires a separate `Relation` (e.g. `parent =
                Relation("parent", subjects=["folder"])`) declaring which
                subject type populates the tupleset relation.

                Also accepts a *list* of `(tupleset_relation,
                computed_relation)` pairs to inherit via more than one
                parent relation, ORed together — e.g.
                `Relation("viewer", from_parent=[("parent_folder",
                "viewer"), ("parent_workspace", "viewer")])` means "the
                user is a viewer via the parent folder OR via the parent
                workspace". Each pair becomes its own `tupleToUserset`
                child.

                When `from_parent` is set and `subjects` is *not*
                explicitly passed, `subjects` defaults to `[]` rather
                than `["user"]`: a relation declared as "inherited from a
                parent" is, by default, not *also* directly assignable —
                pass `subjects=["user"]` explicitly if you want both.

            intersection (Optional[list[str]]):
                Other relation names on the *same object* that must
                **all** hold for this relation to hold (OpenFGA
                `intersection` — a logical AND) — e.g.
                `intersection=["editor", "verified"]` means "the subject
                must be both an editor AND verified". Requires at least 2
                relation names (an "AND" of fewer than 2 is meaningless).
                Composes with `this`/`union`/`inherits`/`from_parent`: the
                intersection becomes just another child ORed alongside
                them (mirroring how OpenFGA nests `intersection` as a
                child of `union`) — so e.g. a relation with both
                `subjects=["user"]` and `intersection=[...]` grants access
                either via a direct tuple OR via the intersection holding.

            exclude (Optional[str]):
                A relation name on the *same object* that, if held,
                revokes this relation even if everything else about it
                (`this`/`union`/`inherits`/`intersection`/`from_parent`)
                would otherwise grant it (OpenFGA `difference` — "base
                MINUS subtract") — e.g. `exclude="banned"` on a `viewer`
                relation means "this relation, minus banned": a subject
                who would otherwise be a viewer is denied if they also
                hold `banned`. Unlike `intersection`, `exclude` wraps the
                *entire* rewrite (it isn't just another `union` child) —
                OpenFGA's `difference` rewrite is a two-operand
                `base`/`subtract` pair, not a list, so there must be a
                base relation-def to subtract from (at least one of
                `subjects`/`union`/`inherits`/`intersection`/
                `from_parent`).
        """
        self.name = name
        self.union = union or []
        self.inherits = inherits or []
        self.intersection = intersection or []
        self.exclude = exclude
        self.from_parent = from_parent

        if subjects is None and from_parent is not None:
            self.subjects: list[str] = []
        else:
            self.subjects = subjects or ["user"]

        self.resource_cls: type[ResourceModel] | None = None

    def bind(self, resource_cls: type[ResourceModel]) -> Relation:
        self.resource_cls = resource_cls
        return self

    def _rebind_copy(self, resource_cls: type[ResourceModel]) -> Relation:
        """
        Return an independent `Relation` with the same configuration as
        this one, bound to `resource_cls` instead.

        Used by `ResourceModelMeta` to give a `ResourceModel` subclass its
        own `Relation` instance for a relation it *inherits* rather than
        redeclares (see ARCH2-23) — without this, two subclasses of a
        common base that both inherit the same `Relation` attribute
        without overriding it would share the literal same object, so
        `.resource_cls` (whichever subclass's metaclass ran `.bind()`
        last) could silently point at the wrong class for the other.
        """
        from_parent = (
            list(self.from_parent) if isinstance(self.from_parent, list) else self.from_parent
        )
        copy = Relation(
            self.name,
            union=list(self.union),
            inherits=list(self.inherits),
            subjects=list(self.subjects),
            from_parent=from_parent,
            intersection=list(self.intersection),
            exclude=self.exclude,
        )
        return copy.bind(resource_cls)

    def __repr__(self) -> str:
        cls_name = self.resource_cls.__name__ if self.resource_cls else "Unbound"
        return f"<Relation {cls_name}.{self.name}>"


class ResourceModelMeta(type):
    """
    Metaclass to automatically bind Relation objects to the resource.

    Every `Relation` visible on a class — whether declared in its own
    class body or inherited from a `ResourceModel` base — ends up bound
    to *that* class specifically, never sharing the same `Relation`
    instance (and therefore the same `.resource_cls`) across two
    different `ResourceModel` subclasses (see ARCH2-23). A relation
    declared directly in a class's own body is bound in place (unchanged,
    original behavior); one only inherited from a base gets an
    independent per-subclass copy instead, so e.g. two subclasses of a
    shared `owner = Relation("owner")` mixin each see
    `resource_cls` pointing at themselves, not at the mixin or at
    whichever sibling subclass happened to be defined last.
    """

    def __new__(mcls, name, bases, namespace):
        cls = super().__new__(mcls, name, bases, namespace)

        for _attr_name, attr_value in namespace.items():
            if isinstance(attr_value, Relation):
                attr_value.bind(cls)

        # Re-bind relations inherited from a base class (i.e. not
        # redeclared in this class's own namespace, so the loop above
        # never touched them) to a fresh copy pinned to `cls`.
        for attr_name in dir(cls):
            if attr_name in namespace:
                continue  # already bound above
            attr_value = getattr(cls, attr_name, None)
            if isinstance(attr_value, Relation) and attr_value.resource_cls is not cls:
                setattr(cls, attr_name, attr_value._rebind_copy(cls))

        return cls


class ResourceModel(metaclass=ResourceModelMeta):
    """
    Base class for defining authorization resource models.

    Example:
        class Document(ResourceModel):
            type = "document"
            view = Relation("viewer")

    Subclassing another `ResourceModel` (e.g. a shared base declaring a
    common `owner = Relation("owner")`) is supported: `ResourceModelMeta`
    gives every subclass its own independent copy of each inherited
    `Relation`, bound to that subclass specifically — see ARCH2-23. You
    never need to worry about two `ResourceModel` subclasses secretly
    sharing (and silently mutating) the same `Relation` instance.
    """

    type: str  # must be defined by subclasses

    def __init__(self, id: str):
        self.id = id

    def to_resource(self):
        """
        Convert to core Resource object.
        """
        from py_authz.core.types import Resource

        return Resource(type=self.type, id=self.id)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} id={self.id}>"

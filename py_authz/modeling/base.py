from __future__ import annotations


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
          the parent folder is a viewer of this document"
    """

    def __init__(
        self,
        name: str,
        *,
        union: list[str] | None = None,
        inherits: list[str] | None = None,
        subjects: list[str] | None = None,
        from_parent: tuple[str, str] | None = None,
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

            from_parent (Optional[tuple[str, str]]):
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

                When `from_parent` is set and `subjects` is *not*
                explicitly passed, `subjects` defaults to `[]` rather
                than `["user"]`: a relation declared as "inherited from a
                parent" is, by default, not *also* directly assignable —
                pass `subjects=["user"]` explicitly if you want both.
        """
        self.name = name
        self.union = union or []
        self.inherits = inherits or []
        self.from_parent = from_parent

        if subjects is None and from_parent is not None:
            self.subjects: list[str] = []
        else:
            self.subjects = subjects or ["user"]

        self.resource_cls: type[ResourceModel] | None = None

    def bind(self, resource_cls: type[ResourceModel]) -> Relation:
        self.resource_cls = resource_cls
        return self

    def __repr__(self) -> str:
        cls_name = self.resource_cls.__name__ if self.resource_cls else "Unbound"
        return f"<Relation {cls_name}.{self.name}>"


class ResourceModelMeta(type):
    """
    Metaclass to automatically bind Relation objects to the resource.
    """

    def __new__(mcls, name, bases, namespace):
        cls = super().__new__(mcls, name, bases, namespace)

        for _, attr_value in namespace.items():
            if isinstance(attr_value, Relation):
                attr_value.bind(cls)

        return cls


class ResourceModel(metaclass=ResourceModelMeta):
    """
    Base class for defining authorization resource models.

    Example:
        class Document(ResourceModel):
            type = "document"
            view = Relation("viewer")
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

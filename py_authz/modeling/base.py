from typing import List, Optional, TYPE_CHECKING, Type

if TYPE_CHECKING:
    from py_authz.modeling.base import ResourceModel


class Relation:
    """
    Represents a relation in the authorization model.

    Supports:
        - direct relations
        - unions (by relation name)
        - computed usersets (inherits)
        - subject types
    """

    def __init__(
        self,
        name: str,
        *,
        union: Optional[List[str]] = None,
        inherits: Optional[List[str]] = None,
        subjects: Optional[List[str]] = None,
    ):
        self.name = name
        self.union = union or []
        self.inherits = inherits or []
        self.subjects = subjects or ["user"]

        self.resource_cls: Optional[Type["ResourceModel"]] = None

    def bind(self, resource_cls: Type["ResourceModel"]) -> "Relation":
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

        for attr_name, attr_value in namespace.items():
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

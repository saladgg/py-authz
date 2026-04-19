from py_authz.core.types import Resource
from py_authz.modeling.base import Relation, ResourceModel


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


def test_relation_binds_to_resource_class():
    assert Doc.view.resource_cls is Doc


def test_relation_repr_shows_bound_class():
    assert "Doc.viewer" in repr(Doc.view)


def test_unbound_relation_repr():
    rel = Relation("orphan")
    assert "Unbound.orphan" in repr(rel)


def test_resource_model_to_resource_returns_core_type():
    doc = Doc("42")
    resource = doc.to_resource()

    assert isinstance(resource, Resource)
    assert resource.type == "document"
    assert resource.id == "42"


def test_resource_model_repr():
    assert "id=42" in repr(Doc("42"))

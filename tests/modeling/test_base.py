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


def test_from_parent_defaults_subjects_to_empty_when_not_explicit():
    """
    A relation declared as "inherited from a parent" is, by default, not
    *also* directly assignable — `subjects` defaults to `[]`, not
    `["user"]`, when `from_parent` is set and `subjects` isn't given.
    """
    rel = Relation("viewer", from_parent=("parent", "viewer"))

    assert rel.from_parent == ("parent", "viewer")
    assert rel.subjects == []


def test_from_parent_respects_explicit_subjects():
    """Passing `subjects` explicitly alongside `from_parent` restores
    direct assignment (both mechanisms can coexist)."""
    rel = Relation("viewer", from_parent=("parent", "viewer"), subjects=["user"])

    assert rel.subjects == ["user"]


def test_relation_without_from_parent_still_defaults_subjects_to_user():
    """Existing (non-from_parent) relations are unaffected."""
    rel = Relation("viewer")

    assert rel.from_parent is None
    assert rel.subjects == ["user"]

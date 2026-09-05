from py_authz.core.types import Resource
from py_authz.modeling.base import Relation, ResourceModel, from_parent_pairs


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


# ----------------------------------------------------------------------
# ARCH2-23: a `Relation` inherited (not redeclared) by two different
# `ResourceModel` subclasses must not be the same shared instance —
# each subclass gets its own copy, independently bound.
# ----------------------------------------------------------------------


class _BaseWithSharedRelation(ResourceModel):
    # Not itself a real "type" a model would generate for — used only to
    # exercise the metaclass's inheritance handling.
    owner = Relation("owner", subjects=["user", "organization"])


class _SubA(_BaseWithSharedRelation):
    type = "sub_a"


class _SubB(_BaseWithSharedRelation):
    type = "sub_b"


def test_inherited_relation_is_independently_bound_per_subclass():
    assert _SubA.owner.resource_cls is _SubA
    assert _SubB.owner.resource_cls is _SubB
    # Neither subclass's copy is the base's own bound instance.
    assert _SubA.owner is not _BaseWithSharedRelation.owner
    assert _SubB.owner is not _BaseWithSharedRelation.owner


def test_inherited_relation_copies_are_distinct_objects_across_subclasses():
    """The two subclasses must not share the literal same `Relation`
    instance — mutating one's copy (e.g. `.bind()`) must never affect
    the other's."""
    assert _SubA.owner is not _SubB.owner


def test_inherited_relation_copy_preserves_configuration():
    """The per-subclass copy carries the same relation config as the
    original — only `.resource_cls` differs."""
    assert _SubA.owner.name == "owner"
    assert _SubA.owner.subjects == ["user", "organization"]


def test_directly_declared_relation_is_still_bound_in_place():
    """A relation declared directly in a class's own body (not
    inherited) keeps the original, pre-ARCH2-23 behavior: it's bound in
    place, not copied."""
    assert Doc.view.resource_cls is Doc


# ----------------------------------------------------------------------
# ARCH2-13: `intersection`, `exclude`, and multi-pair `from_parent`.
# ----------------------------------------------------------------------


def test_intersection_defaults_to_empty_list():
    rel = Relation("access")
    assert rel.intersection == []


def test_intersection_is_stored_as_given():
    rel = Relation("access", intersection=["editor", "verified"])
    assert rel.intersection == ["editor", "verified"]


def test_exclude_defaults_to_none():
    rel = Relation("viewer")
    assert rel.exclude is None


def test_exclude_is_stored_as_given():
    rel = Relation("viewer", exclude="banned")
    assert rel.exclude == "banned"


def test_from_parent_accepts_single_tuple_unchanged():
    rel = Relation("viewer", from_parent=("parent", "viewer"))
    assert rel.from_parent == ("parent", "viewer")


def test_from_parent_accepts_list_of_pairs():
    pairs = [("parent_folder", "viewer"), ("parent_workspace", "viewer")]
    rel = Relation("viewer", from_parent=pairs)
    assert rel.from_parent == pairs


def test_from_parent_list_also_defaults_subjects_to_empty():
    rel = Relation("viewer", from_parent=[("a", "viewer"), ("b", "viewer")])
    assert rel.subjects == []


class _BaseWithIntersectionExcludeAndMultiParent(ResourceModel):
    access = Relation("access", intersection=["editor", "verified"], exclude="banned")
    viewer = Relation(
        "viewer", from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")]
    )


class _SubWithIntersectionEtc(_BaseWithIntersectionExcludeAndMultiParent):
    type = "sub_with_intersection"


def test_rebind_copy_preserves_intersection_exclude_and_multi_from_parent():
    """`ResourceModelMeta`'s per-subclass rebind (ARCH2-23) must carry the
    new fields over too, not just union/inherits/subjects."""
    copy = _SubWithIntersectionEtc.access
    assert copy.resource_cls is _SubWithIntersectionEtc
    assert copy.intersection == ["editor", "verified"]
    assert copy.exclude == "banned"

    viewer_copy = _SubWithIntersectionEtc.viewer
    assert viewer_copy.from_parent == [("parent_folder", "viewer"), ("parent_workspace", "viewer")]
    # Independent list object, not shared with the base's copy.
    assert (
        viewer_copy.from_parent is not _BaseWithIntersectionExcludeAndMultiParent.viewer.from_parent
    )


def test_from_parent_pairs_normalizes_none():
    assert from_parent_pairs(None) == []


def test_from_parent_pairs_normalizes_single_tuple():
    assert from_parent_pairs(("parent", "viewer")) == [("parent", "viewer")]


def test_from_parent_pairs_normalizes_list():
    pairs = [("a", "viewer"), ("b", "viewer")]
    assert from_parent_pairs(pairs) == pairs

import pytest

from py_authz.core.exceptions import ModelValidationError
from py_authz.modeling import Relation, ResourceModel, registry
from py_authz.modeling.generator import OpenFGAModelGenerator


class OrgDoc(ResourceModel):
    type = "org_document"
    owner = Relation("owner", subjects=["user", "organization"])
    editor = Relation("editor", inherits=["owner"])
    viewer = Relation("viewer", union=["editor"])


def test_relation_with_inherits_and_union_generates_union_rewrite():
    registry.register(OrgDoc)
    gen = OpenFGAModelGenerator()

    model = gen.generate()
    types = {t["type"]: t for t in model["type_definitions"]}

    relations = types["org_document"]["relations"]

    # viewer = direct OR editor → emitted as union
    assert "union" in relations["viewer"]
    union_parts = relations["viewer"]["union"]["child"]
    assert {"this": {}} in union_parts
    assert {"computedUserset": {"relation": "editor"}} in union_parts

    # editor = direct OR inherits owner → also union
    assert "union" in relations["editor"]
    editor_parts = relations["editor"]["union"]["child"]
    assert {"computedUserset": {"relation": "owner"}} in editor_parts


def test_metadata_lists_subject_types():
    registry.register(OrgDoc)
    gen = OpenFGAModelGenerator()

    model = gen.generate()
    types = {t["type"]: t for t in model["type_definitions"]}

    metadata = types["org_document"]["metadata"]["relations"]
    owner_subjects = metadata["owner"]["directly_related_user_types"]

    assert {"type": "user"} in owner_subjects
    assert {"type": "organization"} in owner_subjects


def test_build_relation_rejects_a_relation_nothing_can_hold():
    """An explicit `subjects=[]` with no other rewrite would emit an empty
    rewrite OpenFGA rejects — fail at generation time instead."""
    import pytest

    from py_authz.core.exceptions import ModelValidationError

    with pytest.raises(ModelValidationError, match="nothing can ever hold it"):
        OpenFGAModelGenerator()._build_relation(Relation("empty", subjects=[]))


def test_explicit_empty_subjects_is_honoured():
    """ARCH3-4: `subjects=[]` used to be silently replaced with
    `["user"]` (a truthiness check), making every computed relation
    directly grantable."""
    assert Relation("r", subjects=[], union=["owner"]).subjects == []


def test_intersection_relation_is_not_directly_grantable_by_default():
    """ARCH3-4: a direct tuple on an intersection relation would bypass
    its AND entirely, so an intersection defaults to no direct subjects
    (same as `from_parent`)."""
    rel = Relation("access", intersection=["editor", "verified"])

    assert rel.subjects == []
    assert OpenFGAModelGenerator()._build_relation(rel) == {
        "intersection": {
            "child": [
                {"computedUserset": {"relation": "editor"}},
                {"computedUserset": {"relation": "verified"}},
            ]
        }
    }


class Folder(ResourceModel):
    type = "folder"
    viewer = Relation("viewer")


class HierDocument(ResourceModel):
    type = "hier_document"
    parent = Relation("parent", subjects=["folder"])
    viewer = Relation("viewer", from_parent=("parent", "viewer"))


def test_from_parent_emits_pure_tuple_to_userset_with_no_this():
    """
    Regression test for ARCH-2: `from_parent` alone (no explicit
    `subjects`) must emit a bare `tupleToUserset` rewrite — no `this`
    branch, since the relation isn't directly assignable by default.
    """
    registry.register(HierDocument)
    gen = OpenFGAModelGenerator()

    model = gen.generate()
    types = {t["type"]: t for t in model["type_definitions"]}
    relations = types["hier_document"]["relations"]

    assert relations["viewer"] == {
        "tupleToUserset": {
            "tupleset": {"relation": "parent"},
            "computedUserset": {"relation": "viewer"},
        }
    }
    # `parent` itself is a plain direct relation restricted to `folder`.
    assert relations["parent"] == {"this": {}}


def test_from_parent_combines_with_this_when_subjects_explicit():
    rel = Relation("viewer", from_parent=("parent", "viewer"), subjects=["user"])
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert "union" in result
    assert {"this": {}} in result["union"]["child"]
    assert {
        "tupleToUserset": {
            "tupleset": {"relation": "parent"},
            "computedUserset": {"relation": "viewer"},
        }
    } in result["union"]["child"]


def test_parent_relation_metadata_restricts_subject_type():
    registry.register(HierDocument)
    gen = OpenFGAModelGenerator()

    model = gen.generate()
    types = {t["type"]: t for t in model["type_definitions"]}
    metadata = types["hier_document"]["metadata"]["relations"]

    assert metadata["parent"]["directly_related_user_types"] == [{"type": "folder"}]
    # viewer has no direct subjects — empty list, not omitted.
    assert metadata["viewer"]["directly_related_user_types"] == []


# ----------------------------------------------------------------------
# ARCH2-13: intersection, exclude, and multi-pair from_parent.
# ----------------------------------------------------------------------


def test_intersection_emits_intersection_child_alongside_this():
    """Explicit `subjects=["user"]` plus `intersection=[...]` composes:
    this OR (editor AND verified) — intersection nests as just another
    `union` child, matching OpenFGA's own grammar."""
    rel = Relation("access", subjects=["user"], intersection=["editor", "verified"])
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert "union" in result
    child = result["union"]["child"]
    assert {"this": {}} in child
    assert {
        "intersection": {
            "child": [
                {"computedUserset": {"relation": "editor"}},
                {"computedUserset": {"relation": "verified"}},
            ]
        }
    } in child


def test_intersection_alone_with_no_subjects_emits_bare_intersection():
    rel = Relation("access", intersection=["editor", "verified"], subjects=[])
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert result == {
        "intersection": {
            "child": [
                {"computedUserset": {"relation": "editor"}},
                {"computedUserset": {"relation": "verified"}},
            ]
        }
    }


def test_intersection_with_fewer_than_two_relations_raises():
    rel = Relation("access", intersection=["editor"], subjects=[])
    gen = OpenFGAModelGenerator()

    with pytest.raises(ModelValidationError, match="intersection"):
        gen._build_relation(rel)


def test_exclude_wraps_this_in_difference():
    rel = Relation("viewer", exclude="banned")
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert result == {
        "difference": {
            "base": {"this": {}},
            "subtract": {"computedUserset": {"relation": "banned"}},
        }
    }


def test_exclude_wraps_full_union_when_multiple_base_parts():
    rel = Relation("viewer", union=["editor"], exclude="banned")
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert result["difference"]["subtract"] == {"computedUserset": {"relation": "banned"}}
    base = result["difference"]["base"]
    assert "union" in base
    assert {"this": {}} in base["union"]["child"]
    assert {"computedUserset": {"relation": "editor"}} in base["union"]["child"]


def test_exclude_with_no_base_raises():
    rel = Relation("viewer", exclude="banned", subjects=[])
    gen = OpenFGAModelGenerator()

    with pytest.raises(ModelValidationError, match="no base relation-def"):
        gen._build_relation(rel)


def test_exclude_of_self_raises():
    rel = Relation("viewer", exclude="viewer")
    gen = OpenFGAModelGenerator()

    with pytest.raises(ModelValidationError, match="cannot exclude itself"):
        gen._build_relation(rel)


def test_exclude_that_is_also_unioned_raises():
    rel = Relation("viewer", union=["editor"], exclude="editor")
    gen = OpenFGAModelGenerator()

    with pytest.raises(ModelValidationError, match="both includes and excludes"):
        gen._build_relation(rel)


def test_exclude_that_is_also_intersected_raises():
    rel = Relation("access", intersection=["editor", "banned"], exclude="banned")
    gen = OpenFGAModelGenerator()

    with pytest.raises(ModelValidationError, match="both includes and excludes"):
        gen._build_relation(rel)


def test_multi_pair_from_parent_emits_one_tuple_to_userset_child_per_pair():
    rel = Relation(
        "viewer",
        from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")],
    )
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert "union" in result
    child = result["union"]["child"]
    assert {
        "tupleToUserset": {
            "tupleset": {"relation": "parent_folder"},
            "computedUserset": {"relation": "viewer"},
        }
    } in child
    assert {
        "tupleToUserset": {
            "tupleset": {"relation": "parent_workspace"},
            "computedUserset": {"relation": "viewer"},
        }
    } in child


def test_multi_pair_from_parent_single_pair_still_collapses_no_union():
    """A from_parent list with exactly one pair, and no other parts,
    still collapses to a bare `tupleToUserset` (not wrapped in a
    single-child `union`) — same collapsing rule as everything else."""
    rel = Relation("viewer", from_parent=[("parent", "viewer")])
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert result == {
        "tupleToUserset": {
            "tupleset": {"relation": "parent"},
            "computedUserset": {"relation": "viewer"},
        }
    }


def test_intersection_exclude_and_multi_from_parent_combine():
    """Full combination: this OR (editor AND verified) OR
    tupleToUserset(parent_a) OR tupleToUserset(parent_b), all minus
    banned. `subjects=["user"]` passed explicitly since `from_parent`
    alone would otherwise default `subjects` to `[]` (see
    `Relation.__init__`'s `from_parent` docstring)."""
    rel = Relation(
        "access",
        subjects=["user"],
        intersection=["editor", "verified"],
        from_parent=[("parent_a", "access"), ("parent_b", "access")],
        exclude="banned",
    )
    gen = OpenFGAModelGenerator()

    result = gen._build_relation(rel)

    assert set(result.keys()) == {"difference"}
    base = result["difference"]["base"]
    assert result["difference"]["subtract"] == {"computedUserset": {"relation": "banned"}}

    child = base["union"]["child"]
    assert {"this": {}} in child
    assert any("intersection" in c for c in child)
    assert any(
        c.get("tupleToUserset", {}).get("tupleset") == {"relation": "parent_a"} for c in child
    )
    assert any(
        c.get("tupleToUserset", {}).get("tupleset") == {"relation": "parent_b"} for c in child
    )

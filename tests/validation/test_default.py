import pytest

from py_authz.core.exceptions import ModelValidationError
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.generator import OpenFGAModelGenerator
from py_authz.modeling.registry import registry
from py_authz.validation.default import DefaultModelValidator, detect_cycles


@pytest.fixture
def validator():
    return DefaultModelValidator()


def test_validate_accepts_well_formed_model(validator):
    model = {
        "type_definitions": [
            {"type": "user"},
            {
                "type": "document",
                "relations": {"viewer": {"this": {}}},
            },
        ],
    }

    validator.validate(model)


def test_validate_accepts_union_and_computed_userset(validator):
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "viewer": {"union": {"child": []}},
                    "editor": {"computedUserset": {"relation": "viewer"}},
                },
            },
        ],
    }

    validator.validate(model)


def test_validate_accepts_tuple_to_userset(validator):
    """
    Regression test for ARCH-2: a bare `tupleToUserset` rewrite (the shape
    `Relation(from_parent=...)` alone generates — no `this`) must be
    accepted as a valid rewrite, not rejected as "no valid rewrite".
    """
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "parent": {"this": {}},
                    "viewer": {
                        "tupleToUserset": {
                            "tupleset": {"relation": "parent"},
                            "computedUserset": {"relation": "viewer"},
                        }
                    },
                },
            },
        ],
    }

    validator.validate(model)


def test_validate_rejects_model_without_type_definitions(validator):
    with pytest.raises(ModelValidationError, match="type_definitions"):
        validator.validate({})


def test_validate_rejects_type_definition_missing_type(validator):
    with pytest.raises(ModelValidationError, match="Type definition missing"):
        validator.validate({"type_definitions": [{"relations": {}}]})


def test_validate_rejects_non_dict_relation(validator):
    model = {
        "type_definitions": [
            {"type": "document", "relations": {"viewer": "not-a-dict"}},
        ],
    }

    with pytest.raises(ModelValidationError, match="Invalid relation format"):
        validator.validate(model)


def test_validate_accepts_bare_intersection_rewrite(validator):
    """
    Regression test for ARCH2-13: a bare `intersection` rewrite (the
    shape `Relation(intersection=[...], subjects=[])` generates) must be
    accepted as a valid rewrite by the basic shape check, not rejected
    as "no valid rewrite" just because it isn't `this`/`union`/
    `computedUserset`/`tupleToUserset`.
    """
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "editor": {"this": {}},
                    "verified": {"this": {}},
                    "access": {
                        "intersection": {
                            "child": [
                                {"computedUserset": {"relation": "editor"}},
                                {"computedUserset": {"relation": "verified"}},
                            ]
                        }
                    },
                },
            },
        ],
    }

    validator.validate(model)


def test_validate_accepts_bare_difference_rewrite(validator):
    """
    Regression test for ARCH2-13: a bare `difference` rewrite (the shape
    `Relation(exclude=...)` generates) must be accepted as a valid
    rewrite by the basic shape check.
    """
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "banned": {"this": {}},
                    "viewer": {
                        "difference": {
                            "base": {"this": {}},
                            "subtract": {"computedUserset": {"relation": "banned"}},
                        }
                    },
                },
            },
        ],
    }

    validator.validate(model)


def test_validate_rejects_relation_without_known_rewrite(validator):
    model = {
        "type_definitions": [
            {"type": "document", "relations": {"viewer": {"unsupported": {}}}},
        ],
    }

    with pytest.raises(ModelValidationError, match="no valid rewrite"):
        validator.validate(model)


def test_detect_cycles_raises_on_self_loop():
    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles({"a": {"computedUserset": {"relation": "a"}}})


def test_detect_cycles_raises_on_indirect_cycle():
    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles(
            {
                "a": {"computedUserset": {"relation": "b"}},
                "b": {"computedUserset": {"relation": "a"}},
            }
        )


def test_detect_cycles_raises_on_cycle_nested_in_union():
    """
    The common real shape: a relation whose rewrite is a `union` (direct
    assignment `this` OR another relation), where one of the union's
    branches closes a cycle. This is exactly what `OpenFGAModelGenerator`
    emits for `Relation(union=[...])`/`Relation(inherits=[...])`.
    """
    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles(
            {
                "editor": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {"computedUserset": {"relation": "viewer"}},
                        ]
                    }
                },
                "viewer": {
                    "union": {
                        "child": [
                            {"this": {}},
                            {"computedUserset": {"relation": "editor"}},
                        ]
                    }
                },
            }
        )


def test_detect_cycles_acyclic_passes():
    detect_cycles(
        {
            "a": {"computedUserset": {"relation": "b"}},
            "b": {"computedUserset": {"relation": "c"}},
            "c": {"this": {}},
        }
    )


def test_detect_cycles_ignores_tuple_to_userset_cross_type_reference():
    """
    `tupleToUserset`'s `computedUserset` names a relation on a *different*
    object type (reached through the `tupleset` relation) — it must never
    be treated as a same-type dependency, or an ordinary parent-relation
    reference (e.g. "viewer if the parent folder's viewer") would be
    misread as a same-named self-reference.
    """
    detect_cycles(
        {
            "viewer": {
                "union": {
                    "child": [
                        {"this": {}},
                        {
                            "tupleToUserset": {
                                "tupleset": {"relation": "parent"},
                                "computedUserset": {"relation": "viewer"},
                            }
                        },
                    ]
                }
            },
        }
    )


def test_detect_cycles_raises_on_dangling_reference():
    """
    Regression test for ARCH2-12: a typo'd `union=`/`inherits=` reference
    (naming a relation that doesn't exist on this type) used to be
    silently treated as a dead end by the cycle-detection walk instead of
    raising — passing validation, then failing only once uploaded to a
    real OpenFGA server.
    """
    with pytest.raises(ModelValidationError, match="unknown relation 'nonexistent'"):
        detect_cycles({"viewer": {"computedUserset": {"relation": "nonexistent"}}})


def test_validate_raises_on_dangling_reference_end_to_end(validator):
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {"viewer": {"computedUserset": {"relation": "nonexistent"}}},
            },
        ],
    }

    with pytest.raises(ModelValidationError, match="unknown relation"):
        validator.validate(model)


def test_validate_raises_on_circular_relations_end_to_end(validator):
    """
    Regression test for ARCH-3: exercises cycle detection the way it's
    actually invoked — through `DefaultModelValidator.validate()` on a
    full model — rather than calling `detect_cycles` in isolation with a
    hand-built adjacency list that doesn't match what `validate()` passes
    it in production.
    """
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "editor": {"computedUserset": {"relation": "viewer"}},
                    "viewer": {"computedUserset": {"relation": "editor"}},
                },
            },
        ],
    }

    with pytest.raises(ModelValidationError, match="Circular"):
        validator.validate(model)


# ----------------------------------------------------------------------
# ARCH2-13: `_referenced_relations()` already recursed into
# `intersection`/`difference` shapes (added for ARCH-3), but the real
# generator could never actually *produce* them — these confirm the
# generator's real `intersection`/`difference`/multi-`from_parent` output
# is what gets walked here, not a hand-built stand-in for it, and that
# cycle detection reachable only through those branches is caught.
# ----------------------------------------------------------------------


def _generated_relations(*models: type[ResourceModel]) -> dict:
    """
    Register `models` on the process-global `registry` (the same
    singleton `OpenFGAModelGenerator` always reads from — it has no
    injectable-registry seam), generate the *real* model JSON, then
    deregister them again so a deliberately-cyclic test type here can
    never leak into an unrelated test's `generate()`/`validate()` call
    later in the same session.
    """
    for model in models:
        registry.register(model)
    try:
        model_json = OpenFGAModelGenerator().generate()
    finally:
        for model in models:
            del registry._models[model.type]
    types = {t["type"]: t for t in model_json["type_definitions"]}
    # Merge every registered type's relations (each type's own namespace)
    # for the one type under test — cycle detection operates per type.
    return {t: types[t]["relations"] for t in (m.type for m in models)}


def test_cycle_reachable_only_through_intersection_branch_is_detected():
    """`a`'s rewrite is a bare `intersection` of `b`/`c` (no `this`); `b`
    unions back to `a` — a cycle reachable only by recursing into
    `intersection`'s `child` list."""

    class CycleIntersectionDoc(ResourceModel):
        type = "cycle_intersection_doc"

        a = Relation("a", intersection=["b", "c"], subjects=[])
        b = Relation("b", union=["a"])
        c = Relation("c")

    relations = _generated_relations(CycleIntersectionDoc)["cycle_intersection_doc"]

    # Confirm real generator output actually took the intersection shape
    # (not a hand-built stand-in).
    assert "intersection" in relations["a"]

    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles(relations)


def test_cycle_reachable_only_through_difference_branch_is_detected():
    """`viewer`'s rewrite is a `difference` (this OR editor, MINUS
    revoked); `editor` unions back to `viewer` — a cycle reachable only
    by recursing into `difference`'s `base`."""

    class CycleDifferenceDoc(ResourceModel):
        type = "cycle_difference_doc"

        viewer = Relation("viewer", union=["editor"], exclude="revoked")
        editor = Relation("editor", union=["viewer"])
        revoked = Relation("revoked")

    relations = _generated_relations(CycleDifferenceDoc)["cycle_difference_doc"]

    assert "difference" in relations["viewer"]

    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles(relations)


def test_cycle_alongside_multi_from_parent_branch_is_still_detected():
    """`viewer` unions `editor` (closing a cycle) AND is also reachable
    via two `from_parent` pairs — confirms the multiple `tupleToUserset`
    children (correctly ignored as cross-type references) don't hide the
    same-type cycle sitting alongside them in the same `union`."""

    class MultiParentCycleDoc(ResourceModel):
        type = "multi_parent_cycle_doc"

        parent_folder = Relation("parent_folder", subjects=["folder"])
        parent_workspace = Relation("parent_workspace", subjects=["workspace"])
        viewer = Relation(
            "viewer",
            union=["editor"],
            from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")],
        )
        editor = Relation("editor", union=["viewer"])

    relations = _generated_relations(MultiParentCycleDoc)["multi_parent_cycle_doc"]

    child = relations["viewer"]["union"]["child"]
    tuple_to_userset_children = [c for c in child if "tupleToUserset" in c]
    assert len(tuple_to_userset_children) == 2

    with pytest.raises(ModelValidationError, match="Circular"):
        detect_cycles(relations)


def test_intersection_exclude_and_multi_from_parent_pass_full_validator_when_acyclic():
    """The happy path, end to end through `DefaultModelValidator.validate()`:
    a model actually using intersection/exclude/multi-from_parent, with no
    cycle, passes validation."""

    class Folder(ResourceModel):
        type = "acyclic_arch2_13_folder"
        viewer = Relation("viewer")

    class Workspace(ResourceModel):
        type = "acyclic_arch2_13_workspace"
        viewer = Relation("viewer")

    class Doc(ResourceModel):
        type = "acyclic_arch2_13_doc"

        parent_folder = Relation("parent_folder", subjects=["acyclic_arch2_13_folder"])
        parent_workspace = Relation("parent_workspace", subjects=["acyclic_arch2_13_workspace"])
        editor = Relation("editor")
        verified = Relation("verified")
        banned = Relation("banned")
        access = Relation("access", intersection=["editor", "verified"], exclude="banned")
        viewer = Relation(
            "viewer",
            from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")],
        )

    for model in (Folder, Workspace, Doc):
        registry.register(model)

    try:
        validator = DefaultModelValidator()
        validator.validate(OpenFGAModelGenerator().generate())
    finally:
        for model in (Folder, Workspace, Doc):
            del registry._models[model.type]


# ---------------------------------------------------------------------------
# ARCH3-6 — models OpenFGA rejects must fail validation locally
# ---------------------------------------------------------------------------


def _generate(*models):
    return OpenFGAModelGenerator().generate(models=models)


def test_misspelled_tupleset_relation_is_rejected(validator):
    class Folder(ResourceModel):
        type = "arch3_6_folder"
        viewer = Relation("viewer")

    class Doc(ResourceModel):
        type = "arch3_6_doc"
        parent = Relation("parent", subjects=["arch3_6_folder"])
        viewer = Relation("viewer", from_parent=("parnet", "viewer"))

    with pytest.raises(ModelValidationError, match="tupleset relation 'parnet'"):
        validator.validate(_generate(Folder, Doc))


def test_tupleset_computed_relation_missing_on_parent_type_is_rejected(validator):
    class Folder(ResourceModel):
        type = "arch3_6_folder2"
        viewer = Relation("viewer")

    class Doc(ResourceModel):
        type = "arch3_6_doc2"
        parent = Relation("parent", subjects=["arch3_6_folder2"])
        viewer = Relation("viewer", from_parent=("parent", "reader"))

    with pytest.raises(ModelValidationError, match="define 'reader'"):
        validator.validate(_generate(Folder, Doc))


def test_tupleset_nested_in_exclusion_is_checked(validator):
    class Doc(ResourceModel):
        type = "arch3_6_doc3"
        banned = Relation("banned")
        viewer = Relation(
            "viewer", subjects=["user"], from_parent=("nope", "viewer"), exclude="banned"
        )

    with pytest.raises(ModelValidationError, match="tupleset relation 'nope'"):
        validator.validate(_generate(Doc))


def test_unknown_subject_type_is_rejected(validator):
    class Doc(ResourceModel):
        type = "arch3_6_doc4"
        viewer = Relation("viewer", subjects=["grup"])

    with pytest.raises(ModelValidationError, match="subject type 'grup'"):
        validator.validate(_generate(Doc))


def test_userset_subject_with_unknown_relation_is_rejected(validator):
    class Team(ResourceModel):
        type = "arch3_6_team"
        member = Relation("member")

    class Doc(ResourceModel):
        type = "arch3_6_doc5"
        viewer = Relation("viewer", subjects=["arch3_6_team#membr"])

    with pytest.raises(ModelValidationError, match="has no relation 'membr'"):
        validator.validate(_generate(Team, Doc))


def test_wildcard_and_userset_subjects_validate(validator):
    class Team(ResourceModel):
        type = "arch3_6_team2"
        member = Relation("member")

    class Doc(ResourceModel):
        type = "arch3_6_doc6"
        viewer = Relation("viewer", subjects=["user", "user:*", "arch3_6_team2#member"])

    validator.validate(_generate(Team, Doc))


def test_duplicate_type_is_rejected(validator):
    model = {"type_definitions": [{"type": "user"}, {"type": "user"}]}
    with pytest.raises(ModelValidationError, match="defined more than once"):
        validator.validate(model)


def test_tupleset_without_metadata_only_checks_the_same_type(validator):
    """Hand-written models may omit metadata; the parent-type check is
    skipped then, but the tupleset must still exist on the type."""
    model = {
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "parent": {"this": {}},
                    "viewer": {
                        "tupleToUserset": {
                            "tupleset": {"relation": "parent"},
                            "computedUserset": {"relation": "anything"},
                        }
                    },
                },
            }
        ]
    }
    validator.validate(model)


def test_null_difference_branch_is_treated_as_empty(validator):
    """Some JSON serialisers emit an unset field as `null`. A `difference`
    with a null `subtract` must validate on its `base` alone instead of
    crashing — and a bad tupleset in that base is still caught."""
    good = {
        "type_definitions": [
            {"type": "user"},
            {
                "type": "doc",
                "relations": {
                    "owner": {"this": {}},
                    "viewer": {"difference": {"base": {"this": {}}, "subtract": None}},
                },
            },
        ],
    }
    validator.validate(good)

    bad_base = {
        "type_definitions": [
            {"type": "user"},
            {
                "type": "doc",
                "relations": {
                    "viewer": {
                        "difference": {
                            "base": {
                                "tupleToUserset": {
                                    "tupleset": {"relation": "parnet"},
                                    "computedUserset": {"relation": "viewer"},
                                }
                            },
                            "subtract": None,
                        }
                    },
                },
            },
        ],
    }
    with pytest.raises(ModelValidationError, match="'parnet'"):
        validator.validate(bad_base)

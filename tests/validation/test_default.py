import pytest

from py_authz.core.exceptions import ModelValidationError
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

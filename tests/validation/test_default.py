import pytest

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


def test_validate_rejects_model_without_type_definitions(validator):
    with pytest.raises(ValueError, match="type_definitions"):
        validator.validate({})


def test_validate_rejects_type_definition_missing_type(validator):
    with pytest.raises(ValueError, match="Type definition missing"):
        validator.validate({"type_definitions": [{"relations": {}}]})


def test_validate_rejects_non_dict_relation(validator):
    model = {
        "type_definitions": [
            {"type": "document", "relations": {"viewer": "not-a-dict"}},
        ],
    }

    with pytest.raises(ValueError, match="Invalid relation format"):
        validator.validate(model)


def test_validate_rejects_relation_without_known_rewrite(validator):
    model = {
        "type_definitions": [
            {"type": "document", "relations": {"viewer": {"unsupported": {}}}},
        ],
    }

    with pytest.raises(ValueError, match="no valid rewrite"):
        validator.validate(model)


def test_detect_cycles_raises_on_self_loop():
    with pytest.raises(ValueError, match="Circular"):
        detect_cycles({"a": ["a"]})


def test_detect_cycles_raises_on_indirect_cycle():
    with pytest.raises(ValueError, match="Circular"):
        detect_cycles({"a": ["b"], "b": ["a"]})


def test_detect_cycles_acyclic_passes():
    detect_cycles({"a": ["b"], "b": ["c"], "c": []})

from py_authz.core.model_diff import ModelDiffer


def test_normalize_sorts_keys():
    a = {"b": 1, "a": 2}
    b = {"a": 2, "b": 1}

    assert ModelDiffer.normalize(a) == ModelDiffer.normalize(b)


def test_is_equal_true_for_identical_models():
    m = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}

    assert ModelDiffer.is_equal(m, dict(m))


def test_is_equal_ignores_key_ordering():
    a = {"type_definitions": [], "schema_version": "1.1"}
    b = {"schema_version": "1.1", "type_definitions": []}

    assert ModelDiffer.is_equal(a, b)


def test_is_equal_false_when_contents_differ():
    a = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}
    b = {"schema_version": "1.1", "type_definitions": [{"type": "doc"}]}

    assert not ModelDiffer.is_equal(a, b)

from py_authz.core.model_diff import ModelDiffer


def test_normalize_sorts_nested_keys():
    a = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "document", "relations": {"b": 1, "a": 2}}],
    }
    b = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "document", "relations": {"a": 2, "b": 1}}],
    }

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


def test_is_equal_ignores_server_added_metadata():
    """
    A model fetched back from OpenFGA (e.g. `get_latest_model()`) carries
    server-added fields — most notably `id` — that a locally generated
    model never has. Equality must be based on schema fields alone, or a
    freshly-synced, unchanged model would always compare as "different"
    against the server's copy of itself.
    """
    local = {"schema_version": "1.1", "type_definitions": [{"type": "document"}]}
    remote = {
        "id": "01HXYZ000000000000000000",
        "schema_version": "1.1",
        "type_definitions": [{"type": "document"}],
    }

    assert ModelDiffer.is_equal(local, remote)


def test_is_equal_false_when_schema_differs_despite_matching_metadata():
    remote_a = {"id": "same-id", "schema_version": "1.1", "type_definitions": [{"type": "a"}]}
    remote_b = {"id": "same-id", "schema_version": "1.1", "type_definitions": [{"type": "b"}]}

    assert not ModelDiffer.is_equal(remote_a, remote_b)

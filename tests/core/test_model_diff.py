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


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-11: list order must not affect equality —
# `type_definitions`, `directly_related_user_types`, and union/
# intersection `child` lists are all unordered sets semantically.
# ----------------------------------------------------------------------


def test_is_equal_ignores_type_definitions_order():
    a = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "document"}, {"type": "folder"}],
    }
    b = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "folder"}, {"type": "document"}],
    }

    assert ModelDiffer.is_equal(a, b)


def test_is_equal_ignores_directly_related_user_types_order():
    def model(order):
        return {
            "schema_version": "1.1",
            "type_definitions": [
                {
                    "type": "document",
                    "relations": {"viewer": {"this": {}}},
                    "metadata": {
                        "relations": {
                            "viewer": {"directly_related_user_types": order},
                        }
                    },
                }
            ],
        }

    a = model([{"type": "user"}, {"type": "team", "relation": "member"}])
    b = model([{"type": "team", "relation": "member"}, {"type": "user"}])

    assert ModelDiffer.is_equal(a, b)


def test_is_equal_ignores_union_child_order():
    def model(order):
        return {
            "schema_version": "1.1",
            "type_definitions": [
                {
                    "type": "document",
                    "relations": {"viewer": {"union": {"child": order}}},
                }
            ],
        }

    a = model([{"this": {}}, {"computedUserset": {"relation": "editor"}}])
    b = model([{"computedUserset": {"relation": "editor"}}, {"this": {}}])

    assert ModelDiffer.is_equal(a, b)


def test_is_equal_still_false_when_union_child_content_actually_differs():
    """Canonicalization must not make genuinely different models equal."""
    a = {
        "schema_version": "1.1",
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "viewer": {
                        "union": {
                            "child": [
                                {"this": {}},
                                {"computedUserset": {"relation": "editor"}},
                            ]
                        }
                    }
                },
            }
        ],
    }
    b = {
        "schema_version": "1.1",
        "type_definitions": [
            {
                "type": "document",
                "relations": {
                    "viewer": {
                        "union": {
                            "child": [
                                {"this": {}},
                                {"computedUserset": {"relation": "owner"}},
                            ]
                        }
                    }
                },
            }
        ],
    }

    assert not ModelDiffer.is_equal(a, b)


# ----------------------------------------------------------------------
# summarize_diff() — human-readable type/relation-level summary (CP-6:
# backs the control-plane API's model_versions.change_summary).
# ----------------------------------------------------------------------


def test_summarize_diff_with_no_previous_model():
    new_model = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "user"}, {"type": "document", "relations": {"viewer": {}}}],
    }

    summary = ModelDiffer.summarize_diff(None, new_model)

    assert "initial model" in summary
    assert "document" in summary


def test_summarize_diff_reports_added_type():
    old_model = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}
    new_model = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "user"}, {"type": "document", "relations": {"viewer": {}}}],
    }

    summary = ModelDiffer.summarize_diff(old_model, new_model)

    assert "added types=['document']" in summary


def test_summarize_diff_reports_removed_type():
    old_model = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "user"}, {"type": "document", "relations": {}}],
    }
    new_model = {"schema_version": "1.1", "type_definitions": [{"type": "user"}]}

    summary = ModelDiffer.summarize_diff(old_model, new_model)

    assert "removed types=['document']" in summary


def test_summarize_diff_reports_added_and_removed_relations_on_same_type():
    old_model = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "document", "relations": {"owner": {}, "editor": {}}},
        ],
    }
    new_model = {
        "schema_version": "1.1",
        "type_definitions": [
            {"type": "document", "relations": {"owner": {}, "viewer": {}}},
        ],
    }

    summary = ModelDiffer.summarize_diff(old_model, new_model)

    assert "document: +['viewer']" in summary
    assert "document: -['editor']" in summary


def test_summarize_diff_no_change_reports_unchanged():
    model = {
        "schema_version": "1.1",
        "type_definitions": [{"type": "document", "relations": {"owner": {}}}],
    }

    summary = ModelDiffer.summarize_diff(model, model)

    assert summary == "schema unchanged at the type/relation-name level"

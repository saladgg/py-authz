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


def test_build_relation_returns_empty_when_no_parts():
    gen = OpenFGAModelGenerator()

    rel = Relation("empty", subjects=[])
    rel.subjects = []  # ensure direct part is skipped

    result = gen._build_relation(rel)

    assert result == {}

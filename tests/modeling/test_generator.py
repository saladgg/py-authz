from py_authz.modeling import ResourceModel, Relation, registry
from py_authz.modeling.generator import generate_model


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


def test_generate_model():
    registry.register(Doc)

    model = generate_model()

    assert model["schema_version"] == "1.1"

    types = {t["type"]: t for t in model["type_definitions"]}

    assert "document" in types
    assert "viewer" in types["document"]["relations"]

from py_authz.modeling import Relation, ResourceModel, registry
from py_authz.modeling.generator import OpenFGAModelGenerator, generate_model


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


# ----------------------------------------------------------------------
# `models=` (explicit model set, independent of the global registry) —
# what lets a second, independent model (e.g. the control-plane API's
# dogfooded RBAC model) be generated without registering into (or
# reading from) `py_authz.modeling.registry.registry`.
# ----------------------------------------------------------------------


class Widget(ResourceModel):
    type = "widget"
    owner = Relation("owner")


def test_generate_model_with_explicit_models_ignores_global_registry():
    registry.register(Doc)  # global registry has "document" registered

    model = generate_model(models=[Widget])

    types = {t["type"] for t in model["type_definitions"]}
    assert types == {"user", "widget"}  # "document" is NOT pulled in


def test_generate_with_explicit_models_matches_generate_for_that_model():
    via_registry = OpenFGAModelGenerator().generate(models=[Widget])
    types = {t["type"]: t for t in via_registry["type_definitions"]}
    assert "owner" in types["widget"]["relations"]

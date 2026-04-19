import pytest

from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import ModelRegistry


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


def test_register_and_get():
    reg = ModelRegistry()
    reg.register(Doc)

    assert reg.get("document") is Doc
    assert list(reg.all()) == [Doc]


def test_register_rejects_empty_type():
    class Empty(ResourceModel):
        type = ""

    reg = ModelRegistry()

    with pytest.raises(ValueError, match="must define a 'type'"):
        reg.register(Empty)

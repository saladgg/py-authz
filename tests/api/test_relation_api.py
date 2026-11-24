import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity, Resource
from py_authz.modeling import Relation, ResourceModel
from tests.conftest import MockOpenFGAClient


class Doc(ResourceModel):
    type = "document"
    view = Relation("viewer")


@pytest.mark.asyncio
async def test_can_with_relation_and_resource_model():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)
    authz = Authz(engine)

    result = await authz.can(Doc.view, Identity(id="user:1"), Doc("42"))

    assert result is True


@pytest.mark.asyncio
async def test_can_with_relation_rejects_non_resource_model():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    with pytest.raises(TypeError, match="ResourceModel"):
        await authz.can(Doc.view, Identity(id="user:1"), "not-a-model")


# ----------------------------------------------------------------------
# ARCH2-22: `can()`'s `Relation` branch accepts a plain `Resource` too,
# matching `grant`/`revoke`'s existing dual support for either shape.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_can_with_relation_and_matching_plain_resource():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)
    authz = Authz(engine)

    result = await authz.can(Doc.view, Identity(id="user:1"), Resource(type="document", id="42"))

    assert result is True


@pytest.mark.asyncio
async def test_can_with_relation_rejects_mismatched_plain_resource_type():
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    with pytest.raises(TypeError, match="does not match"):
        await authz.can(Doc.view, Identity(id="user:1"), Resource(type="folder", id="42"))


@pytest.mark.asyncio
async def test_can_with_unbound_relation_accepts_any_plain_resource_type():
    """An unbound `Relation` (`resource_cls is None`) has nothing to
    check a plain `Resource`'s `.type` against, so any `Resource` is
    accepted as-is — mirroring `list_objects()`'s handling of unbound
    relations."""
    unbound = Relation("viewer")
    engine = AuthzEngine(fga_client=MockOpenFGAClient(allowed=True), cache=None)
    authz = Authz(engine)

    result = await authz.can(unbound, Identity(id="user:1"), Resource(type="folder", id="1"))

    assert result is True


# ----------------------------------------------------------------------
# Regression coverage for DX2-12: an unbound `Relation` (never assigned
# as a `ResourceModel` class attribute, so `resource_cls` is `None`) must
# raise `TypeError` when no `resource_type` is given — this used to only
# check `resource_type is None`, so a falsy-but-not-`None` `resource_type`
# (e.g. `""`) fell through to an `AttributeError` on `None.type` instead.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_objects_raises_type_error_for_unbound_relation_with_no_resource_type():
    unbound = Relation("viewer")  # never assigned to a ResourceModel class
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    with pytest.raises(TypeError, match="unbound"):
        await authz.list_objects(unbound, Identity(id="user:1"))


@pytest.mark.asyncio
async def test_list_objects_raises_type_error_for_unbound_relation_with_empty_resource_type():
    """The falsy-but-not-None case DX2-12 fixed."""
    unbound = Relation("viewer")
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    with pytest.raises(TypeError, match="unbound"):
        await authz.list_objects(unbound, Identity(id="user:1"), resource_type="")


@pytest.mark.asyncio
async def test_sync_model_requires_fga_client():
    engine = AuthzEngine(fga_client=None, cache=None)
    authz = Authz(engine)

    with pytest.raises(RuntimeError, match="FGA client not configured"):
        await authz.sync_model()


@pytest.mark.asyncio
async def test_sync_model_delegates_to_model_sync(monkeypatch):
    engine = AuthzEngine(fga_client=MockOpenFGAClient(), cache=None)
    authz = Authz(engine)

    class FakeSync:
        def __init__(self, client):
            self.client = client

        async def sync(self):
            return "new-model-id"

    import py_authz.api as api_module

    monkeypatch.setattr(api_module, "ModelSync", FakeSync)

    result = await authz.sync_model()

    assert result == "new-model-id"


@pytest.mark.asyncio
async def test_string_action_with_a_resource_model_instance_is_normalized():
    """ARCH3-5: `can("viewer", user, Doc(id="1"))` used to raise
    `AttributeError: 'Doc' object has no attribute 'to_fga_object'` —
    not an `AuthzError`, so the documented catch-at-the-boundary pattern
    missed it. Same for `enforce()`/`require()`."""
    from py_authz.core.exceptions import AuthorizationDenied
    from py_authz.core.types import Identity
    from py_authz.modeling.base import Relation, ResourceModel
    from py_authz.modeling.registry import ResourceModelRegistry
    from py_authz.testkit import make_fake_authz

    class Doc(ResourceModel):
        type = "doc"
        viewer = Relation("viewer")

    reg = ResourceModelRegistry()
    reg.register(Doc)
    authz = make_fake_authz(model_registry=reg, strict=True)
    alice = Identity(id="user:alice")
    await authz.grant(alice, "viewer", Doc(id="1"))

    assert await authz.can("viewer", alice, Doc(id="1")) is True
    assert await authz.enforce("viewer", alice, Doc(id="2")) is False
    with pytest.raises(AuthorizationDenied):
        await authz.require("viewer", alice, Doc(id="2"))

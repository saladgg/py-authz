"""Tests for py_authz.testkit — the in-memory FGA fake."""

import pytest

from py_authz.core.types import ContextualTuple, Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import ModelRegistry
from py_authz.testkit import InMemoryFGAClient, make_fake_authz


@pytest.fixture
def doc_registry():
    """A fresh registry per test so global state doesn't leak between cases."""

    class Document(ResourceModel):
        type = "document"

        owner = Relation("owner")
        editor = Relation("editor", union=["owner"])
        viewer = Relation("viewer", union=["editor"])

    reg = ModelRegistry()
    reg.register(Document)
    return reg, Document


@pytest.mark.asyncio
async def test_grant_check_revoke_roundtrip(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = Document(id="roadmap")

    assert await authz.can(Document.viewer, alice, doc) is False

    await authz.grant(alice, "viewer", doc.to_resource())
    assert await authz.can(Document.viewer, alice, doc) is True

    await authz.revoke(alice, "viewer", doc.to_resource())
    assert await authz.can(Document.viewer, alice, doc) is False


@pytest.mark.asyncio
async def test_union_edges_resolved_transitively(doc_registry):
    """owner → editor → viewer should all hold when only owner is granted."""
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = Document(id="roadmap")

    await authz.grant(alice, "owner", doc.to_resource())

    assert await authz.can(Document.owner, alice, doc) is True
    assert await authz.can(Document.editor, alice, doc) is True
    assert await authz.can(Document.viewer, alice, doc) is True


@pytest.mark.asyncio
async def test_list_objects_returns_only_authorized(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    bob = Identity(id="user:bob")

    await authz.grant(alice, "owner", Document(id="a").to_resource())
    await authz.grant(alice, "viewer", Document(id="b").to_resource())
    await authz.grant(bob, "owner", Document(id="c").to_resource())

    alice_viewable = await authz.list_objects(Document.viewer, alice)
    assert alice_viewable == ["document:a", "document:b"]

    bob_viewable = await authz.list_objects(Document.viewer, bob)
    assert bob_viewable == ["document:c"]


@pytest.mark.asyncio
async def test_list_objects_with_string_relation(doc_registry):
    reg, _Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    client = authz._engine.fga_client
    await client.write_tuples(
        writes=[{"user": "user:alice", "relation": "owner", "object": "document:a"}]
    )

    result = await authz.list_objects("viewer", alice, "document")
    assert result == ["document:a"]


@pytest.mark.asyncio
async def test_list_objects_requires_resource_type_for_string_relation(doc_registry):
    reg, _Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    with pytest.raises(TypeError):
        await authz.list_objects("viewer", Identity(id="user:alice"))


@pytest.mark.asyncio
async def test_contextual_tuple_grants_access_only_for_that_request(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = Document(id="roadmap")

    # No persisted grant.
    assert await authz.can(Document.viewer, alice, doc) is False

    # With contextual tuple: alice is owner just for this check.
    allowed = await authz.enforce(
        "viewer",
        alice,
        doc.to_resource(),
        contextual_tuples=[ContextualTuple("user:alice", "owner", "document:roadmap")],
    )
    assert allowed is True

    # Persisted state unchanged.
    assert await authz.can(Document.viewer, alice, doc) is False


@pytest.mark.asyncio
async def test_unknown_resource_type_returns_false_without_crashing():
    client = InMemoryFGAClient(model_registry=ModelRegistry())

    # Empty registry, no tuples — must not raise.
    assert await client.check("user:1", "viewer", "unknown:1") is False


@pytest.mark.asyncio
async def test_aclose_is_idempotent_noop():
    client = InMemoryFGAClient()
    await client.aclose()
    await client.aclose()

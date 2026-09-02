"""Tests for py_authz.testkit — the in-memory FGA fake."""

import pytest

from py_authz.core.types import ContextualTuple, Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient, make_fake_authz


@pytest.fixture
def doc_registry():
    """A fresh registry per test so global state doesn't leak between cases."""

    class Document(ResourceModel):
        type = "document"

        owner = Relation("owner")
        editor = Relation("editor", union=["owner"])
        viewer = Relation("viewer", union=["editor"])

    reg = ResourceModelRegistry()
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
async def test_inherits_edges_resolved_same_as_union():
    """
    Regression test for ARCH-7: `Relation(inherits=[...])` must behave
    identically to `union=[...]` in the fake, matching the real generator
    (`modeling/generator.py`), which compiles both to the same
    `computedUserset` rewrite.
    """

    class InheritDoc(ResourceModel):
        type = "inherit_document"

        owner = Relation("owner")
        editor = Relation("editor", inherits=["owner"])
        viewer = Relation("viewer", inherits=["editor"])

    reg = ResourceModelRegistry()
    reg.register(InheritDoc)
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = InheritDoc(id="roadmap")

    await authz.grant(alice, "owner", doc.to_resource())

    assert await authz.can(InheritDoc.owner, alice, doc) is True
    assert await authz.can(InheritDoc.editor, alice, doc) is True
    assert await authz.can(InheritDoc.viewer, alice, doc) is True


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
    client = InMemoryFGAClient(model_registry=ResourceModelRegistry())

    # Empty registry, no tuples — must not raise.
    assert await client.check("user:1", "viewer", "unknown:1") is False


@pytest.mark.asyncio
async def test_aclose_is_idempotent_noop():
    client = InMemoryFGAClient()
    await client.aclose()
    await client.aclose()


@pytest.fixture
def hierarchy_registry():
    """Folder → Document, `viewer` inherited via `from_parent`."""

    class Folder(ResourceModel):
        type = "folder"
        viewer = Relation("viewer")

    class Document(ResourceModel):
        type = "document"
        parent = Relation("parent", subjects=["folder"])
        viewer = Relation("viewer", from_parent=("parent", "viewer"))

    reg = ResourceModelRegistry()
    reg.register(Folder)
    reg.register(Document)
    return reg, Folder, Document


@pytest.mark.asyncio
async def test_from_parent_grants_access_via_parent_relation(hierarchy_registry):
    """
    Regression test for ARCH-2: a viewer of the parent folder must be
    recognized as a viewer of a document inside it, via `from_parent`,
    matching what the real OpenFGA `tupleToUserset` rewrite would do.
    """
    reg, Folder, Document = hierarchy_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    folder = Folder(id="reports")
    doc = Document(id="q3")

    assert await authz.can(Document.viewer, alice, doc) is False

    await authz.grant(alice, "viewer", folder.to_resource())
    # Link doc → folder via the `parent` relation tuple.
    await authz._engine.fga_client.write_tuples(
        writes=[{"user": "folder:reports", "relation": "parent", "object": "document:q3"}]
    )

    assert await authz.can(Document.viewer, alice, doc) is True

    await authz.revoke(alice, "viewer", folder.to_resource())
    assert await authz.can(Document.viewer, alice, doc) is False


@pytest.mark.asyncio
async def test_from_parent_does_not_grant_access_to_unrelated_document(hierarchy_registry):
    reg, Folder, Document = hierarchy_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    folder = Folder(id="reports")
    other_doc = Document(id="unrelated")

    await authz.grant(alice, "viewer", folder.to_resource())
    # No `parent` tuple linking `other_doc` to `folder` — must stay denied.
    assert await authz.can(Document.viewer, alice, other_doc) is False

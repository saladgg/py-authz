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


# ----------------------------------------------------------------------
# ARCH2-13: intersection, exclude, and multi-pair from_parent — fake
# parity with the real generator's new rewrite shapes.
# ----------------------------------------------------------------------


@pytest.fixture
def intersection_exclude_registry():
    class Doc(ResourceModel):
        type = "arch2_13_doc"

        editor = Relation("editor")
        verified = Relation("verified")
        banned = Relation("banned")
        access = Relation("access", intersection=["editor", "verified"], subjects=[])
        viewer = Relation("viewer", exclude="banned")

    reg = ResourceModelRegistry()
    reg.register(Doc)
    return reg, Doc


@pytest.mark.asyncio
async def test_intersection_requires_all_named_relations(intersection_exclude_registry):
    reg, Doc = intersection_exclude_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = Doc(id="d1")

    assert await authz.can(Doc.access, alice, doc) is False

    await authz.grant(alice, "editor", doc.to_resource())
    assert await authz.can(Doc.access, alice, doc) is False  # editor only, not verified yet

    await authz.grant(alice, "verified", doc.to_resource())
    assert await authz.can(Doc.access, alice, doc) is True  # both now held


@pytest.mark.asyncio
async def test_exclude_revokes_access_even_with_direct_grant(intersection_exclude_registry):
    reg, Doc = intersection_exclude_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")
    doc = Doc(id="d1")

    await authz.grant(alice, "viewer", doc.to_resource())
    assert await authz.can(Doc.viewer, alice, doc) is True

    await authz.grant(alice, "banned", doc.to_resource())
    assert await authz.can(Doc.viewer, alice, doc) is False  # banned overrides direct viewer grant


@pytest.fixture
def multi_from_parent_registry():
    class Folder(ResourceModel):
        type = "arch2_13_folder"
        viewer = Relation("viewer")

    class Workspace(ResourceModel):
        type = "arch2_13_workspace"
        viewer = Relation("viewer")

    class Document(ResourceModel):
        type = "arch2_13_multi_parent_doc"
        parent_folder = Relation("parent_folder", subjects=["arch2_13_folder"])
        parent_workspace = Relation("parent_workspace", subjects=["arch2_13_workspace"])
        viewer = Relation(
            "viewer",
            from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")],
        )

    reg = ResourceModelRegistry()
    reg.register(Folder)
    reg.register(Workspace)
    reg.register(Document)
    return reg, Folder, Workspace, Document


@pytest.mark.asyncio
async def test_multi_from_parent_grants_via_either_parent(multi_from_parent_registry):
    reg, Folder, Workspace, Document = multi_from_parent_registry
    authz = make_fake_authz(model_registry=reg)

    alice = Identity(id="user:alice")  # viewer via folder only
    bob = Identity(id="user:bob")  # viewer via workspace only
    carol = Identity(id="user:carol")  # viewer via neither

    doc = Document(id="d1")
    folder = Folder(id="f1")
    workspace = Workspace(id="w1")

    await authz.grant(alice, "viewer", folder.to_resource())
    await authz.grant(bob, "viewer", workspace.to_resource())

    await authz._engine.fga_client.write_tuples(
        writes=[
            {
                "user": "arch2_13_folder:f1",
                "relation": "parent_folder",
                "object": "arch2_13_multi_parent_doc:d1",
            },
            {
                "user": "arch2_13_workspace:w1",
                "relation": "parent_workspace",
                "object": "arch2_13_multi_parent_doc:d1",
            },
        ]
    )

    assert await authz.can(Document.viewer, alice, doc) is True
    assert await authz.can(Document.viewer, bob, doc) is True
    assert await authz.can(Document.viewer, carol, doc) is False

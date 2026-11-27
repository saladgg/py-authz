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
async def test_read_tuples_filters_by_each_field(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)
    alice = Identity(id="user:alice")
    bob = Identity(id="user:bob")

    await authz.grant(alice, "owner", Document(id="d1"))
    await authz.grant(bob, "viewer", Document(id="d2"))

    all_tuples = await authz._engine.fga_client.read_tuples()
    assert len(all_tuples["tuples"]) == 2
    assert all_tuples["continuation_token"] is None

    by_user = await authz._engine.fga_client.read_tuples(user="user:alice")
    assert by_user["tuples"] == [
        {"user": "user:alice", "relation": "owner", "object": "document:d1", "timestamp": None}
    ]

    by_object = await authz._engine.fga_client.read_tuples(object="document:d2")
    assert len(by_object["tuples"]) == 1
    assert by_object["tuples"][0]["user"] == "user:bob"

    none_match = await authz._engine.fga_client.read_tuples(relation="editor")
    assert none_match["tuples"] == []


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


# ---------------------------------------------------------------------------
# ARCH3-9: relation lookup by OpenFGA name, and strict mode
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_relations_are_looked_up_by_their_openfga_name_not_attribute_name():
    """`view = Relation("viewer", ...)` defines relation `viewer` — the
    real generator keys on `Relation.name`, so the fake must too."""

    class Doc(ResourceModel):
        type = "doc"

        edit = Relation("editor")
        view = Relation("viewer", union=["editor"])

    reg = ResourceModelRegistry()
    reg.register(Doc)
    authz = make_fake_authz(model_registry=reg)
    alice = Identity(id="user:alice")
    await authz.grant(alice, "editor", Doc(id="1"))

    assert await authz.can("viewer", alice, Doc(id="1").to_resource()) is True
    assert await authz.can(Doc.view, alice, Doc(id="1")) is True


@pytest.mark.asyncio
async def test_read_tuples_accepts_a_bare_type_as_object_filter(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)
    alice = Identity(id="user:alice")
    await authz.grant(alice, "owner", Document(id="d1"))
    await authz.grant(alice, "viewer", Document(id="d2"))

    result = await authz.read_tuples(user="user:alice", object="document:")

    assert {t["object"] for t in result["tuples"]} == {"document:d1", "document:d2"}


@pytest.fixture
def strict_authz(doc_registry):
    reg, Document = doc_registry
    return make_fake_authz(model_registry=reg, strict=True), Document


@pytest.mark.asyncio
async def test_strict_rejects_an_undefined_user_type(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected as ExternalServiceError

    authz, Document = strict_authz
    with pytest.raises(ExternalServiceError, match="type 'service' not found"):
        await authz.grant(Identity(id="service:ci-bot"), "owner", Document(id="d1"))
    with pytest.raises(ExternalServiceError):
        await authz.can("viewer", Identity(id="service:ci-bot"), Document(id="d1").to_resource())


@pytest.mark.asyncio
async def test_strict_rejects_undefined_types_and_relations(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected as ExternalServiceError
    from py_authz.core.types import Resource

    authz, Document = strict_authz
    alice = Identity(id="user:alice")
    with pytest.raises(ExternalServiceError, match="relation"):
        await authz.grant(alice, "approver", Document(id="d1"))
    with pytest.raises(ExternalServiceError, match="type 'folder'"):
        await authz.can("viewer", alice, Resource(type="folder", id="f1"))


@pytest.mark.asyncio
async def test_strict_rejects_a_subject_type_the_relation_does_not_allow():
    from py_authz.core.exceptions import UpstreamRequestRejected as ExternalServiceError

    class Team(ResourceModel):
        type = "team"
        member = Relation("member")

    class Doc(ResourceModel):
        type = "doc"
        owner = Relation("owner")  # subjects default to ["user"]

    reg = ResourceModelRegistry()
    reg.register(Team)
    reg.register(Doc)
    authz = make_fake_authz(model_registry=reg, strict=True)

    with pytest.raises(ExternalServiceError, match="not an allowed subject"):
        await authz.grant(Identity(id="team:core"), "owner", Doc(id="1"))


@pytest.mark.asyncio
async def test_strict_rejects_duplicate_writes_and_missing_deletes_atomically(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected as ExternalServiceError

    authz, Document = strict_authz
    client = authz._engine.fga_client
    alice = {"user": "user:alice", "relation": "owner", "object": "document:d1"}
    bob = {"user": "user:bob", "relation": "owner", "object": "document:d1"}

    await client.write_tuples([alice])
    with pytest.raises(ExternalServiceError, match="already exists"):
        await client.write_tuples([bob, alice])  # batch rejected as a whole...
    assert (await client.read_tuples(user="user:bob"))["tuples"] == []  # ...nothing applied

    with pytest.raises(ExternalServiceError, match="does not exist"):
        await client.write_tuples([], deletes=[bob])


@pytest.mark.asyncio
async def test_non_strict_mode_stays_permissive_for_backwards_compatibility(doc_registry):
    reg, Document = doc_registry
    authz = make_fake_authz(model_registry=reg)

    await authz.grant(Identity(id="service:anything"), "owner", Document(id="d1"))
    await authz.grant(Identity(id="service:anything"), "owner", Document(id="d1"))


@pytest.mark.asyncio
async def test_strict_validates_contextual_tuples_on_check(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected

    authz, Document = strict_authz
    alice = Identity(id="user:alice")
    doc = Document(id="d1")

    ok = ContextualTuple(user="user:alice", relation="owner", object="document:d1")
    assert await authz.can("viewer", alice, doc, contextual_tuples=[ok]) is True

    bad = ContextualTuple(user="user:alice", relation="approver", object="document:d1")
    with pytest.raises(UpstreamRequestRejected, match="approver"):
        await authz.can("viewer", alice, doc, contextual_tuples=[bad])


@pytest.mark.asyncio
async def test_strict_validates_list_objects_queries(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected

    authz, Document = strict_authz
    alice = Identity(id="user:alice")
    await authz.grant(alice, "owner", Document(id="d1"))

    assert await authz.list_objects("viewer", alice, "document") == ["document:d1"]
    with pytest.raises(UpstreamRequestRejected, match="approver"):
        await authz.list_objects("approver", alice, "document")


@pytest.mark.asyncio
async def test_strict_rejects_a_user_without_a_type_prefix(strict_authz):
    from py_authz.core.exceptions import UpstreamRequestRejected

    authz, Document = strict_authz
    with pytest.raises(UpstreamRequestRejected, match="must be of the form 'type:id'"):
        await authz.grant(Identity(id="alice"), "owner", Document(id="d1"))


@pytest.mark.asyncio
async def test_strict_accepts_wildcard_and_userset_subjects_the_relation_declares():
    from py_authz.core.exceptions import UpstreamRequestRejected

    class Team(ResourceModel):
        type = "team"
        member = Relation("member")

    class Doc(ResourceModel):
        type = "doc"
        viewer = Relation("viewer", subjects=["user", "user:*", "team#member"])
        owner = Relation("owner")  # subjects default to ["user"]

    reg = ResourceModelRegistry()
    reg.register(Team)
    reg.register(Doc)
    client = InMemoryFGAClient(model_registry=reg, strict=True)

    await client.write_tuples(
        [
            {"user": "user:*", "relation": "viewer", "object": "doc:public"},
            {"user": "team:core#member", "relation": "viewer", "object": "doc:1"},
        ]
    )
    assert len((await client.read_tuples(relation="viewer"))["tuples"]) == 2
    # The wildcard grants every user (as real OpenFGA does), but not a
    # userset subject or the wildcard "user" itself.
    assert await client.check("user:anyone", "viewer", "doc:public") is True
    assert await client.check("team:core#member", "viewer", "doc:public") is False
    assert await client.check("user:*", "viewer", "doc:2") is False
    assert await client.check("user:anyone", "viewer", "doc:1") is False

    with pytest.raises(UpstreamRequestRejected, match="'user:\\*' is not an allowed subject"):
        await client.write_tuples([{"user": "user:*", "relation": "owner", "object": "doc:1"}])
    with pytest.raises(UpstreamRequestRejected, match="'team#member' is not an allowed subject"):
        await client.write_tuples(
            [{"user": "team:core#member", "relation": "owner", "object": "doc:1"}]
        )


@pytest.mark.asyncio
async def test_relations_inherited_from_a_base_model_class_are_resolved():
    class Shared(ResourceModel):
        type = "shared"
        owner = Relation("owner")
        viewer = Relation("viewer", union=["owner"])

    class Report(Shared):
        type = "report"

    reg = ResourceModelRegistry()
    reg.register(Report)
    authz = make_fake_authz(model_registry=reg)
    alice = Identity(id="user:alice")

    await authz.grant(alice, "owner", Report(id="r1"))

    assert await authz.can("viewer", alice, Report(id="r1")) is True


@pytest.mark.asyncio
async def test_cyclic_relation_definitions_terminate_as_denied():
    """A model whose relations imply each other in a loop (which the real
    validator would reject) must not recurse forever in the fake."""

    class Loop(ResourceModel):
        type = "loop"
        a = Relation("a", union=["b"])
        b = Relation("b", union=["a"])

    reg = ResourceModelRegistry()
    reg.register(Loop)
    authz = make_fake_authz(model_registry=reg)

    assert await authz.can("a", Identity(id="user:alice"), Loop(id="1")) is False


@pytest.mark.asyncio
async def test_contextual_wildcard_tuple_grants_every_user_of_the_type():
    client = InMemoryFGAClient()
    wildcard = [{"user": "user:*", "relation": "viewer", "object": "doc:x"}]

    assert await client.check("user:a", "viewer", "doc:x", contextual_tuples=wildcard) is True
    assert await client.check("user:a", "viewer", "doc:x") is False
    # Only users of the wildcard's type match.
    assert await client.check("bot:a", "viewer", "doc:x", contextual_tuples=wildcard) is False

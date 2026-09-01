"""
Regression coverage for ARCH-2 (parent-relation inheritance /
`tupleToUserset`), against a real OpenFGA instance.

`InMemoryFGAClient` (testkit) and the JSON-shape unit tests in
`tests/modeling/`/`tests/validation/` all confirm `from_parent` produces
the *intended* `tupleToUserset` rewrite and that the fake evaluates it the
same way — but only a real OpenFGA server can confirm the generated model
is actually accepted and evaluated as a real `tupleToUserset` rewrite
would be. This mirrors the folder→document hierarchy from the approved
design (`docs/todos/01_architecture_and_modeling_todos.md`, ARCH-2).
"""

import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.model_sync import ModelSync
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry

from .conftest import requires_openfga


class LiveFolder(ResourceModel):
    type = "live_hier_folder"

    viewer = Relation("viewer")


class LiveHierDocument(ResourceModel):
    type = "live_hier_document"

    parent = Relation("parent", subjects=["live_hier_folder"])
    viewer = Relation("viewer", from_parent=("parent", "viewer"))


registry.register(LiveFolder)
registry.register(LiveHierDocument)


@pytest.fixture
async def live_authz(live_client):
    await ModelSync(live_client).sync(force=True)
    return Authz(AuthzEngine(fga_client=live_client))


@requires_openfga
@pytest.mark.asyncio
async def test_folder_viewer_inherits_to_document_via_real_openfga(live_authz):
    alice = Identity(id="user:alice")
    folder = LiveFolder(id="reports")
    doc = LiveHierDocument(id="q3")

    assert await live_authz.enforce("viewer", alice, doc.to_resource()) is False

    await live_authz.grant(alice, "viewer", folder)
    await live_authz._engine.fga_client.write_tuples(
        writes=[
            {
                "user": "live_hier_folder:reports",
                "relation": "parent",
                "object": "live_hier_document:q3",
            }
        ]
    )

    assert await live_authz.enforce("viewer", alice, doc.to_resource()) is True


@requires_openfga
@pytest.mark.asyncio
async def test_document_without_parent_tuple_stays_denied(live_authz):
    alice = Identity(id="user:alice")
    folder = LiveFolder(id="reports")
    unrelated_doc = LiveHierDocument(id="unrelated")

    await live_authz.grant(alice, "viewer", folder)
    # No `parent` tuple linking `unrelated_doc` to `folder`.

    assert await live_authz.enforce("viewer", alice, unrelated_doc.to_resource()) is False

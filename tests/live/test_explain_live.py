"""
ARCH3-8 against a real OpenFGA: `explain()` returns the actual route
(via `/expand`), not just the check result.
"""

import pytest

from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.generator import generate_model

from .conftest import requires_openfga


class LiveExplainTeam(ResourceModel):
    type = "live_explain_team"
    member = Relation("member")


class LiveExplainFolder(ResourceModel):
    type = "live_explain_folder"
    editor = Relation("editor", subjects=["user", "live_explain_team#member"])


class LiveExplainDoc(ResourceModel):
    type = "live_explain_doc"
    parent = Relation("parent", subjects=["live_explain_folder"])
    owner = Relation("owner")
    editor = Relation("editor", union=["owner"], from_parent=("parent", "editor"))
    viewer = Relation("viewer", subjects=["user", "user:*"], union=["editor"])


@requires_openfga
@pytest.mark.asyncio
async def test_explain_reports_the_real_route(live_client):
    model = generate_model(models=[LiveExplainTeam, LiveExplainFolder, LiveExplainDoc])
    await live_client.write_authorization_model(model)
    engine = AuthzEngine(fga_client=live_client)

    alice = Identity(id="user:alice")
    doc = LiveExplainDoc(id="plan")
    await live_client.write_tuples(
        writes=[
            {"user": "user:alice", "relation": "member", "object": "live_explain_team:core"},
            {
                "user": "live_explain_team:core#member",
                "relation": "editor",
                "object": "live_explain_folder:eng",
            },
            {
                "user": "live_explain_folder:eng",
                "relation": "parent",
                "object": "live_explain_doc:plan",
            },
        ]
    )

    result = await engine.explain(_request("viewer", alice, doc))

    assert result.allowed is True
    assert result.path == [
        "live_explain_doc:plan#viewer",
        "live_explain_doc:plan#editor",
        "live_explain_folder:eng#editor",
        "live_explain_team:core#member",
        "user:alice",
    ]

    # Public access through the wildcard.
    await live_client.write_tuples(
        writes=[{"user": "user:*", "relation": "viewer", "object": "live_explain_doc:pub"}]
    )
    public = await engine.explain(
        _request("viewer", Identity(id="user:bob"), LiveExplainDoc(id="pub"))
    )
    assert public.allowed is True
    assert public.path == ["live_explain_doc:pub#viewer", "user:*"]

    denied = await engine.explain(_request("viewer", Identity(id="user:eve"), doc))
    assert denied.allowed is False
    assert denied.path is None


def _request(action, identity, model):
    return AuthzRequest(identity=identity, action=action, resource=model.to_resource())

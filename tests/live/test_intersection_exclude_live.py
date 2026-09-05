"""
Regression coverage for ARCH2-13 (`intersection`/`exclude`/multi-pair
`from_parent`), against a real OpenFGA instance.

The JSON-shape unit tests in `tests/modeling/`, the cycle-detection tests
in `tests/validation/test_default.py`, and the in-memory-fake tests in
`tests/test_testkit.py` all confirm `Relation(intersection=...)`,
`Relation(exclude=...)`, and `Relation(from_parent=[...])` produce the
*intended* `intersection`/`difference`/`tupleToUserset` rewrites and that
the fake evaluates them the same way — but only a real OpenFGA server can
confirm the generated model is actually accepted and evaluated as a real
`intersection`/`difference` rewrite would be. This mirrors
`test_hierarchy_live.py`'s ARCH-2 precedent for `from_parent`.
"""

import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.model_sync import ModelSync
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry

from .conftest import requires_openfga


class LiveArch213Folder(ResourceModel):
    type = "live_arch2_13_folder"

    viewer = Relation("viewer")


class LiveArch213Workspace(ResourceModel):
    type = "live_arch2_13_workspace"

    viewer = Relation("viewer")


class LiveArch213Document(ResourceModel):
    type = "live_arch2_13_document"

    parent_folder = Relation("parent_folder", subjects=["live_arch2_13_folder"])
    parent_workspace = Relation("parent_workspace", subjects=["live_arch2_13_workspace"])

    editor = Relation("editor")
    verified = Relation("verified")
    banned = Relation("banned")

    # "editor AND verified" — OpenFGA `intersection`.
    access = Relation("access", intersection=["editor", "verified"], subjects=[])

    # "viewer EXCLUDE banned" — OpenFGA `difference`.
    safe_viewer = Relation("safe_viewer", exclude="banned")

    # "viewer via parent folder OR via parent workspace" — two
    # `tupleToUserset` children ORed together.
    viewer = Relation(
        "viewer",
        from_parent=[("parent_folder", "viewer"), ("parent_workspace", "viewer")],
    )


registry.register(LiveArch213Folder)
registry.register(LiveArch213Workspace)
registry.register(LiveArch213Document)


@pytest.fixture
async def live_authz(live_client):
    await ModelSync(live_client).sync(force=True)
    return Authz(AuthzEngine(fga_client=live_client))


# ----------------------------------------------------------------------
# intersection
# ----------------------------------------------------------------------


@requires_openfga
@pytest.mark.asyncio
async def test_intersection_denies_with_only_one_side_held(live_authz):
    alice = Identity(id="user:alice")
    doc = LiveArch213Document(id="d1")

    assert await live_authz.enforce("access", alice, doc.to_resource()) is False

    await live_authz.grant(alice, "editor", doc)
    assert await live_authz.enforce("access", alice, doc.to_resource()) is False


@requires_openfga
@pytest.mark.asyncio
async def test_intersection_allows_when_both_sides_held(live_authz):
    alice = Identity(id="user:alice")
    doc = LiveArch213Document(id="d1")

    await live_authz.grant(alice, "editor", doc)
    await live_authz.grant(alice, "verified", doc)

    assert await live_authz.enforce("access", alice, doc.to_resource()) is True


# ----------------------------------------------------------------------
# exclude (difference)
# ----------------------------------------------------------------------


@requires_openfga
@pytest.mark.asyncio
async def test_exclude_allows_plain_viewer(live_authz):
    bob = Identity(id="user:bob")
    doc = LiveArch213Document(id="d1")

    await live_authz.grant(bob, "safe_viewer", doc)
    assert await live_authz.enforce("safe_viewer", bob, doc.to_resource()) is True


@requires_openfga
@pytest.mark.asyncio
async def test_exclude_denies_viewer_who_is_also_banned(live_authz):
    bob = Identity(id="user:bob")
    doc = LiveArch213Document(id="d1")

    await live_authz.grant(bob, "safe_viewer", doc)
    assert await live_authz.enforce("safe_viewer", bob, doc.to_resource()) is True

    await live_authz.grant(bob, "banned", doc)
    assert await live_authz.enforce("safe_viewer", bob, doc.to_resource()) is False


# ----------------------------------------------------------------------
# multi-pair from_parent
# ----------------------------------------------------------------------


@requires_openfga
@pytest.mark.asyncio
async def test_multi_from_parent_grants_via_either_parent_relation(live_authz):
    carol = Identity(id="user:carol")  # viewer of the folder only
    dave = Identity(id="user:dave")  # viewer of the workspace only
    erin = Identity(id="user:erin")  # viewer of neither

    doc = LiveArch213Document(id="d1")
    folder = LiveArch213Folder(id="f1")
    workspace = LiveArch213Workspace(id="w1")

    await live_authz.grant(carol, "viewer", folder)
    await live_authz.grant(dave, "viewer", workspace)

    await live_authz._engine.fga_client.write_tuples(
        writes=[
            {
                "user": "live_arch2_13_folder:f1",
                "relation": "parent_folder",
                "object": "live_arch2_13_document:d1",
            },
            {
                "user": "live_arch2_13_workspace:w1",
                "relation": "parent_workspace",
                "object": "live_arch2_13_document:d1",
            },
        ]
    )

    assert await live_authz.enforce("viewer", carol, doc.to_resource()) is True
    assert await live_authz.enforce("viewer", dave, doc.to_resource()) is True
    assert await live_authz.enforce("viewer", erin, doc.to_resource()) is False

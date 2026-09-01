"""
Grant/check/revoke round trip through `Authz`, against a real OpenFGA
instance. Locks in that the tuple-write and check payload shapes
`clients/openfga.py` builds are actually accepted by a real server, not
just a scripted mock.
"""

import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.model_sync import ModelSync
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry

from .conftest import requires_openfga


class LiveTupleDocument(ResourceModel):
    type = "live_tuple_document"

    owner = Relation("owner")
    editor = Relation("editor", union=["owner"])
    viewer = Relation("viewer", union=["editor"])


registry.register(LiveTupleDocument)


@pytest.fixture
async def live_authz(live_client):
    await ModelSync(live_client).sync(force=True)
    return Authz(AuthzEngine(fga_client=live_client))


@requires_openfga
@pytest.mark.asyncio
async def test_grant_check_revoke_round_trip(live_authz):
    alice = Identity(id="user:alice")
    doc = LiveTupleDocument(id="roadmap")

    assert await live_authz.enforce("viewer", alice, doc.to_resource()) is False

    await live_authz.grant(alice, "owner", doc)

    # `owner` implies `editor` implies `viewer` via the union chain.
    assert await live_authz.enforce("owner", alice, doc.to_resource()) is True
    assert await live_authz.enforce("editor", alice, doc.to_resource()) is True
    assert await live_authz.enforce("viewer", alice, doc.to_resource()) is True

    await live_authz.revoke(alice, "owner", doc)

    assert await live_authz.enforce("viewer", alice, doc.to_resource()) is False


@requires_openfga
@pytest.mark.asyncio
async def test_list_objects_returns_granted_resources(live_authz):
    alice = Identity(id="user:alice")
    doc_a = LiveTupleDocument(id="a")
    doc_b = LiveTupleDocument(id="b")

    await live_authz.grant(alice, "owner", doc_a)
    await live_authz.grant(alice, "viewer", doc_b)

    objects = await live_authz.list_objects(LiveTupleDocument.viewer, alice)

    assert set(objects) == {"live_tuple_document:a", "live_tuple_document:b"}


@requires_openfga
@pytest.mark.asyncio
async def test_grant_many_over_100_tuples_is_chunked_against_real_openfga(live_authz):
    """
    Regression test for REL-8: a real OpenFGA server rejects a single
    Write request with more than 100 combined tuple operations. Before
    `OpenFGAClient.write_tuples()` chunked, `grant_many()` over that count
    raised an `ExternalServiceError` from OpenFGA's real 400 response —
    this confirms the chunking actually lets a real >100-tuple grant
    succeed and that every tuple lands.
    """
    alice = Identity(id="user:alice")
    docs = [LiveTupleDocument(id=f"bulk-{i}") for i in range(120)]

    await live_authz.grant_many([(alice, "owner", doc) for doc in docs])

    objects = await live_authz.list_objects(LiveTupleDocument.viewer, alice)

    assert {doc.to_resource().to_fga_object() for doc in docs} <= set(objects)

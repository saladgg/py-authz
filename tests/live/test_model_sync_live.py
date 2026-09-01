"""
Regression coverage for ARCH-1, run against a real OpenFGA instance.

`ModelSync.sync()`'s "reuse the existing model if unchanged" path reads a
field (`current_model["id"]`) from OpenFGA's actual list-authorization-
models response — every other test in the suite mocks that response, so
none of them would have caught the original bug (reading
`authorization_model_id`, a key that only exists on the *write* endpoint's
response). These tests exercise the real HTTP round trip.
"""

import pytest

from py_authz.core.model_sync import ModelSync
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry

from .conftest import requires_openfga


class LiveSyncDocument(ResourceModel):
    type = "live_sync_document"

    owner = Relation("owner")
    viewer = Relation("viewer", union=["owner"])


registry.register(LiveSyncDocument)


@requires_openfga
@pytest.mark.asyncio
async def test_sync_is_idempotent_against_real_openfga(live_client):
    syncer = ModelSync(live_client)

    first_model_id = await syncer.sync()
    second_model_id = await syncer.sync()

    assert first_model_id == second_model_id

    current = await live_client.get_latest_model()
    assert current["id"] == first_model_id


@requires_openfga
@pytest.mark.asyncio
async def test_sync_force_uploads_a_new_model_even_when_unchanged(live_client):
    syncer = ModelSync(live_client)

    first_model_id = await syncer.sync()
    forced_model_id = await syncer.sync(force=True)

    # OpenFGA assigns a fresh model id to every write, even when the
    # uploaded schema is byte-for-byte identical to what's already there.
    assert forced_model_id != first_model_id

    current = await live_client.get_latest_model()
    assert current["id"] == forced_model_id

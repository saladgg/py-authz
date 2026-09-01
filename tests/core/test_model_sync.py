import pytest

from py_authz.modeling.generator import generate_model


class MockFGAClient:
    def __init__(self, *, existing_model=None):
        self.store_id = "store123"
        self.model_id = None
        self._existing_model = existing_model
        self.post_calls: list[tuple[str, dict]] = []

    async def get_latest_model(self):
        return self._existing_model

    async def _post(self, path, json):
        self.post_calls.append((path, json))
        return {"authorization_model_id": "new-model-id"}


@pytest.mark.asyncio
async def test_model_sync_uploads_when_no_existing_model():
    from py_authz.core.model_sync import ModelSync

    client = MockFGAClient(existing_model=None)

    sync = ModelSync(client)

    model_id = await sync.sync()

    assert model_id == "new-model-id"
    assert client.model_id == "new-model-id"
    assert client.post_calls, "expected the model to be uploaded"


@pytest.mark.asyncio
async def test_model_sync_reuses_existing_model_when_unchanged():
    """
    Regression test for ARCH-1.

    `get_latest_model()` returns an OpenFGA-shaped item — keyed "id" (not
    "authorization_model_id", which only appears on the *write* endpoint's
    response) and carrying whatever schema the current registry generates.
    `sync()` must recognize it as unchanged and reuse its "id" rather than
    raising `KeyError` or re-uploading a model that hasn't actually changed.
    """
    from py_authz.core.model_sync import ModelSync

    generated = generate_model()
    existing_model = {"id": "existing-model-id", **generated}

    client = MockFGAClient(existing_model=existing_model)

    sync = ModelSync(client)

    model_id = await sync.sync()

    assert model_id == "existing-model-id"
    assert client.model_id is None  # never overwritten — no upload happened
    assert client.post_calls == []


@pytest.mark.asyncio
async def test_model_sync_reuploads_when_schema_changed():
    from py_authz.core.model_sync import ModelSync

    existing_model = {
        "id": "stale-model-id",
        "schema_version": "1.1",
        "type_definitions": [{"type": "__nonexistent_marker__"}],
    }

    client = MockFGAClient(existing_model=existing_model)

    sync = ModelSync(client)

    model_id = await sync.sync()

    assert model_id == "new-model-id"
    assert client.post_calls, "expected a re-upload since the schema changed"


@pytest.mark.asyncio
async def test_model_sync_force_always_uploads():
    from py_authz.core.model_sync import ModelSync

    generated = generate_model()
    existing_model = {"id": "existing-model-id", **generated}

    client = MockFGAClient(existing_model=existing_model)

    sync = ModelSync(client)

    model_id = await sync.sync(force=True)

    assert model_id == "new-model-id"
    assert client.post_calls, "force=True must upload even when unchanged"

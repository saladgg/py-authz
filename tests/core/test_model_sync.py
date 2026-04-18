import pytest


class MockFGAClient:
    def __init__(self):
        self.store_id = "store123"
        self.model_id = None

    async def get_latest_model(self):
        return None

    async def _post(self, path, json):
        return {"authorization_model_id": "new-model-id"}


@pytest.mark.asyncio
async def test_model_sync():
    from py_authz.core.model_sync import ModelSync

    client = MockFGAClient()

    sync = ModelSync(client)

    model_id = await sync.sync()

    assert model_id == "new-model-id"
    assert client.model_id == "new-model-id"

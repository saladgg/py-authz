import pytest

from py_authz.cli.commands import sync as sync_module
from py_authz.cli.commands.sync import sync_command


class FakeOpenFGAClient:
    instances: list["FakeOpenFGAClient"] = []

    def __init__(self, *, api_url, store_id, model_id):
        self.api_url = api_url
        self.store_id = store_id
        self.model_id = model_id
        FakeOpenFGAClient.instances.append(self)


class FakeModelSync:
    instances: list["FakeModelSync"] = []

    def __init__(self, fga_client, validator=None):
        self.fga_client = fga_client
        self.validator = validator
        self.sync_calls: list[bool] = []
        FakeModelSync.instances.append(self)

    async def sync(self, force=False):
        self.sync_calls.append(force)
        return "model-from-sync"


@pytest.fixture(autouse=True)
def patch_sync_dependencies(monkeypatch):
    FakeOpenFGAClient.instances = []
    FakeModelSync.instances = []
    monkeypatch.setattr(sync_module, "OpenFGAClient", FakeOpenFGAClient)
    monkeypatch.setattr(sync_module, "ModelSync", FakeModelSync)


@pytest.mark.asyncio
async def test_sync_command_uses_cli_args_when_provided(capsys):
    await sync_command(
        store_id="store-1",
        api_url="http://fake",
        model_id="model-1",
        force=True,
    )

    assert FakeOpenFGAClient.instances[0].store_id == "store-1"
    assert FakeOpenFGAClient.instances[0].api_url == "http://fake"
    assert FakeModelSync.instances[0].sync_calls == [True]

    captured = capsys.readouterr()
    assert "model-from-sync" in captured.out


@pytest.mark.asyncio
async def test_sync_command_falls_back_to_env(monkeypatch, capsys):
    monkeypatch.setenv("FGA_STORE_ID", "env-store")
    monkeypatch.setenv("FGA_API_URL", "http://env-host")
    monkeypatch.delenv("FGA_MODEL_ID", raising=False)

    await sync_command()

    client = FakeOpenFGAClient.instances[0]
    assert client.store_id == "env-store"
    assert client.api_url == "http://env-host"
    assert client.model_id is None

    assert FakeModelSync.instances[0].validator is not None
    captured = capsys.readouterr()
    assert "model-from-sync" in captured.out

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.model_sync import ModelSync
from py_authz.cli.config import get_env


async def sync_command(
    *,
    store_id: str | None = None,
    api_url: str | None = None,
    model_id: str | None = None,
    force: bool = False,
):
    # Resolve config (CLI args take precedence over env)
    store_id = store_id or get_env("FGA_STORE_ID", required=True)
    api_url = api_url or get_env("FGA_API_URL", required=True)
    model_id = model_id or get_env("FGA_MODEL_ID", default=None)

    client = OpenFGAClient(
        api_url=api_url,
        store_id=store_id,
        model_id=model_id,
    )

    syncer = ModelSync(client)

    new_model_id = await syncer.sync(force=force)

    print(f"Active model: {new_model_id}")

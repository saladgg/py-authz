import json

from py_authz.cli.config import get_env
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.model_sync import ModelSync
from py_authz.validation.default import DefaultModelValidator


async def sync_command(
    *,
    store_id: str | None = None,
    api_url: str | None = None,
    model_id: str | None = None,
    force: bool = False,
    json_output: bool = False,
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

    validator = DefaultModelValidator()

    syncer = ModelSync(client, validator=validator)
    new_model_id = await syncer.sync(force=force)

    if json_output:
        # Opt-in machine-readable output for CI pipelines (see DX2-15) —
        # the human-readable line below was the only shape available
        # before, and free-text like "Active model: ..." has to be
        # line-parsed by any caller that wants the model ID back.
        print(json.dumps({"store_id": store_id, "active_model_id": new_model_id}))
    else:
        print(f"Active model: {new_model_id}")

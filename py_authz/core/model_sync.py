from typing import Any

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.model_diff import ModelDiffer
from py_authz.modeling.generator import generate_model


class ModelSync:
    """
    Handles syncing generated models to OpenFGA.

    Now supports:
        - diffing
        - idempotent sync
    """

    def __init__(self, fga_client: OpenFGAClient):
        self.fga_client = fga_client

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    async def sync(self, force: bool = False) -> str:
        """
        Sync model with OpenFGA.

        Args:
            force (bool):
                If True, always upload model.

        Returns:
            str: active model_id
        """
        new_model = generate_model()

        current_model = await self._get_current_model()

        # -------------------------------------------------
        # Diff check
        # -------------------------------------------------
        if not force and current_model and ModelDiffer.is_equal(new_model, current_model):
            # No change → reuse existing model
            return current_model["authorization_model_id"]

        # -------------------------------------------------
        # Upload new model
        # -------------------------------------------------
        model_id = await self._upload_model(new_model)

        self.fga_client.model_id = model_id

        return model_id

    # -------------------------------------------------------------------
    # Internals
    # -------------------------------------------------------------------

    async def _get_current_model(self) -> dict[str, Any] | None:
        model = await self.fga_client.get_latest_model()
        return model

    async def _upload_model(self, model: dict[str, Any]) -> str:
        response = await self.fga_client._post(
            f"/stores/{self.fga_client.store_id}/authorization-models",
            json=model,
        )

        return response["authorization_model_id"]

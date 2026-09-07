from collections.abc import Callable
from typing import Any

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.model_diff import ModelDiffer
from py_authz.modeling.generator import generate_model
from py_authz.validation.default import DefaultModelValidator


class ModelSync:
    """
    Handles syncing generated models to OpenFGA.

    Now supports:
        - diffing
        - idempotent sync
    """

    def __init__(
        self,
        fga_client: OpenFGAClient,
        validator: DefaultModelValidator | None = None,
        *,
        model_factory: Callable[[], dict[str, Any]] | None = None,
    ):
        """
        Args:
            model_factory: Zero-argument callable returning the model to
                sync. Defaults to `generate_model` (reads the global
                `py_authz.modeling.registry.registry` singleton, same as
                always). Pass e.g. `functools.partial(generate_model,
                models=MY_MODELS)` (or any other zero-arg callable) to
                sync a model built from an explicit set of `ResourceModel`
                classes instead — what lets a second, independent model
                (e.g. the control-plane API's dogfooded RBAC model,
                `control_plane/rbac_model.py`) reuse this class's
                diff/idempotent-sync logic without registering into (or
                reading from) that shared global registry.
        """
        self.fga_client = fga_client
        self.validator = validator
        self._model_factory = model_factory or generate_model
        #: Set by `sync()`: whether the just-completed call actually
        #: uploaded a new model (`True`) or found the current one already
        #: matched and reused it (`False`). `None` before `sync()` is ever
        #: called. This is what `MigrationManager` reads instead of
        #: comparing against its own separately-tracked "current model"
        #: (see ARCH2-17) — `sync()` already knows the answer from its own
        #: real-time diff against OpenFGA, so a second, independently-
        #: updated source of truth for the same fact can only drift.
        self.last_sync_changed: bool | None = None

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
        new_model = self._model_factory()
        if self.validator:
            self.validator.validate(new_model)

        current_model = await self._get_current_model()

        # -------------------------------------------------
        # Diff check
        # -------------------------------------------------
        if not force and current_model and ModelDiffer.is_equal(new_model, current_model):
            # No change → reuse existing model.
            #
            # NOTE: `current_model` comes from OpenFGA's list-models
            # response (`get_latest_model()`), where each item is keyed
            # "id" — NOT "authorization_model_id" (that key only appears
            # on the *write* endpoint's response, see `_upload_model`
            # below). Reading the wrong key here silently defeated this
            # whole no-op path against a real OpenFGA server.
            self.last_sync_changed = False
            return current_model["id"]

        # -------------------------------------------------
        # Upload new model
        # -------------------------------------------------
        model_id = await self._upload_model(new_model)

        self.fga_client.model_id = model_id
        self.last_sync_changed = True

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

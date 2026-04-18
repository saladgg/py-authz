from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.core.model_sync import ModelSync

from py_authz.core.tenant_resolver import TenantResolver
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine


class Authz:
    """
    High-level authorization interface.

    This is the primary entry point for developers using py-authz.
    It provides a simple and expressive API for enforcing permissions.

    Example:
        authz = Authz(engine)

        allowed = await authz.enforce(
            action="view",
            user=Identity(id="user:123"),
            resource=Resource(type="document", id="456"),
        )
    """

    def __init__(self, engine: AuthzEngine):
        """
        Initialize the Authz interface.

        Args:
            engine (AuthzEngine):
                Core authorization engine instance.
        """
        self._engine = engine

    async def enforce(
        self,
        action: str,
        user: Identity,
        resource: Resource,
        *,
        context: dict | None = None,
    ) -> bool:
        """
        Enforce an authorization decision.

        Args:
            action (str):
                Action to check (e.g., "viewer", "editor").

            user (Identity):
                The subject performing the action.

            resource (Resource):
                The target resource.

            context (Optional[dict]):
                Optional contextual data (future use).

        Returns:
            bool:
                True if access is allowed, False otherwise.

        Raises:
            AuthzError:
                If an error occurs during authorization.
        """
        request = AuthzRequest(
            identity=user,
            action=action,
            resource=resource,
            context=context,
        )

        return await self._engine.enforce(request)

    async def can(
        self,
        action,
        user,
        resource,
    ):
        """
        Supports both:
            - string actions ("viewer")
            - Relation objects (Document.view)
        """

        # -------------------------------------------------
        # Relation-based API
        # -------------------------------------------------
        if isinstance(action, Relation):
            relation = action.name

            if isinstance(resource, ResourceModel):
                resource_obj = resource.to_resource()
            else:
                raise TypeError("Resource must be a ResourceModel instance")

        # -------------------------------------------------
        # String-based API (backward compatibility)
        # -------------------------------------------------
        else:
            relation = action
            resource_obj = resource

        return await self.enforce(
            action=relation,
            user=user,
            resource=resource_obj,
        )

    async def require(
        self,
        action: str,
        user: Identity,
        resource: Resource,
    ) -> None:
        """
        Enforce permission and raise if denied.

        This is useful in cases where denial should interrupt execution.

        Example:
            await authz.require("edit", user, document)

        Raises:
            AuthorizationDenied:
                If access is denied.
        """
        # Temporarily override behavior
        original = self._engine.raise_on_denied
        self._engine.raise_on_denied = True

        try:
            await self.enforce(action, user, resource)
        finally:
            # Restore original behavior
            self._engine.raise_on_denied = original

    async def sync_model(self) -> str:
        """
        Generate and sync model with OpenFGA.

        Returns:
            str: new model_id
        """
        if not self.engine.fga_client:
            raise RuntimeError("FGA client not configured")

        syncer = ModelSync(self.engine.fga_client)
        return await syncer.sync()


class MultiTenantAuthz:
    """
    Multi-tenant wrapper around Authz.
    """

    def __init__(
        self,
        *,
        api_url: str,
        model_id: str | None,
        tenant_resolver,
        tenant_manager=None,
    ):
        self.api_url = api_url
        self.model_id = model_id
        self.tenant_resolver = tenant_resolver
        self.tenant_manager = tenant_manager

        self._cache = {}

    async def for_tenant(self, tenant_id: str):
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        try:
            store_id = await self.tenant_resolver.resolve(tenant_id)
        except Exception:
            if not self.tenant_manager:
                raise

            # Auto-provision tenant
            store_id = await self.tenant_manager.provision(tenant_id)

        client = OpenFGAClient(
            api_url=self.api_url,
            store_id=store_id,
            model_id=self.model_id,
        )

        engine = AuthzEngine(fga_client=client)

        from py_authz.api import Authz

        authz = Authz(engine)

        self._cache[tenant_id] = authz

        return authz

from typing import Optional

from py_authz.core.types import Identity, Resource, AuthzRequest
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
        context: Optional[dict] = None,
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
        action: str,
        user: Identity,
        resource: Resource,
    ) -> bool:
        """
        Convenience method for checking permissions.

        Alias for `enforce`, designed for readability.

        Example:
            if await authz.can("view", user, document):
                ...

        Args:
            action (str)
            user (Identity)
            resource (Resource)

        Returns:
            bool
        """
        return await self.enforce(action, user, resource)

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
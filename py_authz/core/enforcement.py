from py_authz.cache.base import BaseCache
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import (
    AuthorizationDenied,
    InvalidAuthzRequest,
)
from py_authz.core.types import AuthzRequest


class AuthzEngine:
    """
    Core authorization engine responsible for enforcing access control.

    This class orchestrates:
        - Authorization checks via OpenFGA
        - Caching for performance
        - Validation of incoming requests

    It is the central component of the py-authz library.
    """

    def __init__(
        self,
        fga_client: OpenFGAClient,
        cache: BaseCache | None = None,
        *,
        raise_on_denied: bool = False,
    ):
        """
        Initialize the authorization engine.

        Args:
            fga_client (OpenFGAClient):
                Client used to communicate with OpenFGA.

            cache (Optional[BaseCache]):
                Optional cache backend.

            raise_on_denied (bool):
                If True, raises AuthorizationDenied instead of returning False.
        """
        self.fga_client = fga_client
        self.cache = cache
        self.raise_on_denied = raise_on_denied

    async def enforce(self, request: AuthzRequest) -> bool:
        """
        Enforce an authorization decision.

        Args:
            request (AuthzRequest):
                The authorization request.

        Returns:
            bool:
                True if access is allowed, False otherwise.

        Raises:
            InvalidAuthzRequest:
                If the request is malformed.

            AuthorizationDenied:
                If access is denied and raise_on_denied=True.
        """
        self._validate_request(request)

        cache_key = request.cache_key()

        # -------------------------------------------------
        # 1. Check cache
        # -------------------------------------------------
        if self.cache:
            cached = await self.cache.get(cache_key)
            if cached is not None:
                return self._handle_result(cached, request)

        # -------------------------------------------------
        # 2. Call OpenFGA
        # -------------------------------------------------
        allowed = await self.fga_client.check(
            user=request.identity.id,
            relation=request.action,
            object=request.resource.to_fga_object(),
        )

        # -------------------------------------------------
        # 3. Cache result
        # -------------------------------------------------
        if self.cache:
            await self.cache.set(cache_key, allowed)

        # -------------------------------------------------
        # 4. Return / raise
        # -------------------------------------------------
        return self._handle_result(allowed, request)

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _validate_request(self, request: AuthzRequest) -> None:
        """
        Validate the authorization request.

        Args:
            request (AuthzRequest)

        Raises:
            InvalidAuthzRequest: If validation fails.
        """
        if not request.identity or not request.identity.id:
            raise InvalidAuthzRequest("Missing or invalid identity")

        if not request.action:
            raise InvalidAuthzRequest("Action must be provided")

        if not request.resource:
            raise InvalidAuthzRequest("Resource must be provided")

        if not request.resource.type or not request.resource.id:
            raise InvalidAuthzRequest("Invalid resource format")

    def _handle_result(self, allowed: bool, request: AuthzRequest) -> bool:
        """
        Handle the authorization result.

        Args:
            allowed (bool): Result from OpenFGA or cache
            request (AuthzRequest)

        Returns:
            bool

        Raises:
            AuthorizationDenied:
                If access is denied and raise_on_denied=True
        """
        if not allowed and self.raise_on_denied:
            raise AuthorizationDenied(
                f"Access denied for {request.identity.id} "
                f"to perform '{request.action}' on "
                f"{request.resource.to_fga_object()}"
            )

        return allowed

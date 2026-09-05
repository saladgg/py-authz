from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from py_authz.adapters.keycloak import KeycloakJWTValidator
from py_authz.core.exceptions import AuthenticationError, ExternalServiceError
from py_authz.utils.deps import require_fast_api

_, HTTPException, status = require_fast_api()


class KeycloakAuthMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware to:
        - Extract Bearer token
        - Validate JWT
        - Attach Identity to request.state.user
    """

    def __init__(self, app, validator: KeycloakJWTValidator):
        super().__init__(app)
        self.validator = validator

    async def dispatch(self, request: Request, call_next):  # type: ignore
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return await call_next(request)

        # `.removeprefix(...)` rather than `.split(" ")[1]` — the latter
        # produced an empty (and confusingly-wrong) token on any header
        # with irregular whitespace or a token that itself contains a
        # space (neither is spec-mandated, just possible). Safe either
        # way (a mangled token still fails cleanly via
        # `AuthenticationError` below), just a clearer failure mode.
        token = auth_header.removeprefix("Bearer ")

        try:
            payload = await self.validator.validate(token)
            identity = self.validator.to_identity(payload)

            request.state.user = identity

        except AuthenticationError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication",
            ) from e

        except ExternalServiceError as e:
            # The identity provider itself is unreachable (e.g.
            # `IdentityProviderUnavailable` from a failed discovery/JWKS
            # fetch) — distinct from "this token is invalid": a 503, not
            # a 401, so an IdP outage isn't indistinguishable from a bad
            # credential (see ARCH2-7).
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Identity provider unavailable",
            ) from e

        return await call_next(request)

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from py_authz.adapters.keycloak import KeycloakJWTValidator
from py_authz.core.exceptions import AuthenticationError, ExternalServiceError
from py_authz.utils.deps import require_fast_api

_, _HTTPException, status = require_fast_api()


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

        # Responses are *returned*, not raised (SEC3-14): this runs inside
        # `BaseHTTPMiddleware.dispatch`, outside the routing layer where
        # FastAPI's `HTTPException` handlers live — a raised HTTPException
        # escaped as an unhandled error, so every invalid token produced a
        # 500 (still failing closed, but noisy and indistinguishable from
        # a real server fault).
        except AuthenticationError:
            return JSONResponse(
                status_code=status.HTTP_401_UNAUTHORIZED,
                content={"detail": "Invalid authentication"},
                headers={"WWW-Authenticate": "Bearer"},
            )

        except ExternalServiceError:
            # The identity provider itself is unreachable (e.g.
            # `IdentityProviderUnavailable` from a failed discovery/JWKS
            # fetch) — distinct from "this token is invalid": a 503, not
            # a 401, so an IdP outage isn't indistinguishable from a bad
            # credential (see ARCH2-7).
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={"detail": "Identity provider unavailable"},
            )

        return await call_next(request)

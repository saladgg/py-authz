from starlette.requests import Request
from starlette.middleware.base import BaseHTTPMiddleware
from fastapi import HTTPException, status

from py_authz.adapters.keycloak import KeycloakJWTValidator
from py_authz.core.exceptions import AuthenticationError


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

    async def dispatch(self, request: Request, call_next):
        auth_header = request.headers.get("Authorization")

        if not auth_header or not auth_header.startswith("Bearer "):
            return await call_next(request)

        token = auth_header.split(" ")[1]

        try:
            payload = await self.validator.validate(token)
            identity = self.validator.to_identity(payload)

            request.state.user = identity

        except AuthenticationError:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid authentication",
            )

        return await call_next(request)

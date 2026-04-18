from typing import Optional, Dict, Any

import jwt
import httpx

from py_authz.core.types import Identity
from py_authz.core.exceptions import AuthenticationError


class KeycloakJWTValidator:
    """
    Validates and decodes JWT tokens issued by Keycloak.

    Features:
        - Fetches JWKS (public keys)
        - Verifies signature
        - Extracts user identity
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
    ):
        """
        Args:
            issuer (str):
                Keycloak issuer URL
                e.g. https://auth.example.com/realms/myrealm

            audience (str):
                Expected audience (client_id)
        """
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.jwks_url = f"{self.issuer}/protocol/openid-connect/certs"

        self._jwks: Optional[Dict[str, Any]] = None

    # -------------------------------------------------------------------
    # JWKS Fetching
    # -------------------------------------------------------------------

    async def _fetch_jwks(self) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            res = await client.get(self.jwks_url)
            res.raise_for_status()
            return res.json()

    async def _get_jwks(self) -> Dict[str, Any]:
        if self._jwks is None:
            self._jwks = await self._fetch_jwks()
        return self._jwks

    # -------------------------------------------------------------------
    # Token Validation
    # -------------------------------------------------------------------

    async def validate(self, token: str) -> Dict[str, Any]:
        """
        Validate JWT and return decoded payload.
        """
        try:
            jwks = await self._get_jwks()

            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header["kid"]

            key = next(
                (k for k in jwks["keys"] if k["kid"] == kid),
                None,
            )

            if not key:
                raise AuthenticationError("Invalid token: unknown kid")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

            payload = jwt.decode(
                token,
                public_key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
            )

            return payload

        except jwt.ExpiredSignatureError:
            raise AuthenticationError("Token expired")

        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}")

    # -------------------------------------------------------------------
    # Identity Extraction
    # -------------------------------------------------------------------

    def to_identity(self, payload: Dict[str, Any]) -> Identity:
        """
        Convert JWT payload → Identity
        """
        sub = payload.get("sub")

        if not sub:
            raise AuthenticationError("Missing 'sub' in token")

        return Identity(id=f"user:{sub}")

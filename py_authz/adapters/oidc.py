import time
from typing import Any

import httpx
import jwt  # type: ignore[import-not-found]

from py_authz.core.exceptions import AuthenticationError
from py_authz.core.types import Identity


class OIDCJWTValidator:
    """
    Generic OpenID Connect JWT validator.

    Works with any standards-compliant OIDC provider — Auth0, Okta, AWS
    Cognito, or any other issuer that publishes a discovery document at
    `{issuer}/.well-known/openid-configuration` — not just Keycloak.
    `KeycloakJWTValidator` is a thin subclass that passes a deterministic
    `jwks_url` explicitly (Keycloak's JWKS path never needs discovery).

    Features:
        - Resolves the JWKS endpoint via OIDC discovery (or an explicit
          `jwks_url`, skipping that round trip)
        - Fetches JWKS (public keys), refetching once (rate-limited) on an
          unrecognized `kid` in case the provider rotated its signing keys
        - Verifies signature (RS256 only, explicitly — never inferred from
          the token's own header, which would allow an algorithm-downgrade
          attack)
        - Extracts user identity
    """

    #: Algorithms accepted for signature verification. Passed explicitly to
    #: `jwt.decode` — never taken from the token's own (attacker-controlled)
    #: header.
    ALGORITHMS = ["RS256"]

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_url: str | None = None,
        jwks_refresh_cooldown: float = 60.0,
    ):
        """
        Args:
            issuer (str):
                OIDC issuer URL, e.g. https://auth.example.com/realms/myrealm
                or https://your-tenant.auth0.com/.

            audience (str):
                Expected audience (client ID / API identifier).

            jwks_url (Optional[str]):
                Explicit JWKS endpoint. If omitted, resolved from the
                provider's OIDC discovery document
                (`{issuer}/.well-known/openid-configuration`'s `jwks_uri`)
                the first time it's needed.

            jwks_refresh_cooldown (float):
                Minimum seconds between forced JWKS refetches (triggered by
                an unrecognized `kid` — see `_get_jwks`). Prevents a client
                sending arbitrary/garbage `kid` values from forcing
                unlimited refetches against the provider's JWKS endpoint.
        """
        self.issuer = issuer.rstrip("/")
        self.audience = audience

        self._explicit_jwks_url = jwks_url
        self._discovery: dict[str, Any] | None = None

        self._jwks: dict[str, Any] | None = None
        self._jwks_refresh_cooldown = jwks_refresh_cooldown
        self._last_refresh_at: float | None = None

    # -------------------------------------------------------------------
    # Discovery + JWKS Fetching
    # -------------------------------------------------------------------

    async def _resolve_jwks_url(self) -> str:
        """
        Return the JWKS endpoint, resolving it via the provider's OIDC
        discovery document on first use if not given explicitly.
        """
        if self._explicit_jwks_url:
            return self._explicit_jwks_url

        if self._discovery is None:
            async with httpx.AsyncClient() as client:
                res = await client.get(f"{self.issuer}/.well-known/openid-configuration")
                res.raise_for_status()
                self._discovery = res.json()

        return self._discovery["jwks_uri"]

    async def _fetch_jwks(self) -> dict[str, Any]:
        jwks_url = await self._resolve_jwks_url()
        async with httpx.AsyncClient() as client:
            res = await client.get(jwks_url)
            res.raise_for_status()
            return res.json()

    async def _get_jwks(self, *, force_refresh: bool = False) -> dict[str, Any]:
        """
        Return the cached JWKS, fetching it on first use.

        `force_refresh=True` bypasses the cache — used when a token's
        `kid` isn't found in it, since the provider may have rotated its
        signing keys since we last fetched. Forced refreshes are
        rate-limited by `jwks_refresh_cooldown` (tracked independently of
        the initial cache fill, so the *first* forced refresh right after
        startup is never blocked) so they can't be triggered more often
        than that, regardless of how many mismatched `kid`s arrive.
        """
        if not force_refresh:
            if self._jwks is None:
                self._jwks = await self._fetch_jwks()
            return self._jwks

        now = time.monotonic()
        cooldown_elapsed = (
            self._last_refresh_at is None
            or (now - self._last_refresh_at) >= self._jwks_refresh_cooldown
        )

        if self._jwks is None or cooldown_elapsed:
            self._jwks = await self._fetch_jwks()
            self._last_refresh_at = now

        return self._jwks

    @staticmethod
    def _find_key(jwks: dict[str, Any], kid: str) -> dict[str, Any] | None:
        return next((k for k in jwks["keys"] if k["kid"] == kid), None)

    # -------------------------------------------------------------------
    # Token Validation
    # -------------------------------------------------------------------

    async def validate(self, token: str) -> dict[str, Any]:
        """
        Validate JWT and return decoded payload.
        """
        try:
            jwks = await self._get_jwks()

            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header["kid"]

            key = self._find_key(jwks, kid)

            if not key:
                # Unknown kid: the provider may have rotated its signing
                # keys since we last cached the JWKS. Refetch once
                # (subject to the cooldown) before giving up, so a routine
                # key rotation doesn't require restarting this process to
                # recover trust.
                jwks = await self._get_jwks(force_refresh=True)
                key = self._find_key(jwks, kid)

            if not key:
                raise AuthenticationError("Invalid token: unknown kid")

            public_key = jwt.algorithms.RSAAlgorithm.from_jwk(key)

            payload = jwt.decode(
                token,
                public_key,
                algorithms=self.ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
            )

            return payload

        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("Token expired") from e

        except jwt.InvalidAudienceError as e:
            raise AuthenticationError(self._audience_error_message(e)) from e

        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}") from e

    def _audience_error_message(self, exc: Exception) -> str:
        """
        Overridable so a subclass can name provider-specific configuration
        steps (see `KeycloakJWTValidator`'s override) — audience
        misconfiguration is one of the most common first-integration
        failures and a generic "invalid token" message leaves the
        integrator with no lead on what to fix.
        """
        return (
            f"Invalid token: audience mismatch — the token's 'aud' claim "
            f"does not include the expected audience {self.audience!r}. "
            f"Check that this OIDC provider's client/application/API "
            f"identifier is configured to issue tokens with that audience."
        )

    # -------------------------------------------------------------------
    # Identity Extraction
    # -------------------------------------------------------------------

    def to_identity(self, payload: dict[str, Any]) -> Identity:
        """
        Convert JWT payload → Identity
        """
        sub = payload.get("sub")

        if not sub:
            raise AuthenticationError("Missing 'sub' in token")

        return Identity(id=f"user:{sub}")

import asyncio
import time
from typing import Any

import httpx
import jwt  # type: ignore[import-not-found]

from py_authz.core.exceptions import AuthenticationError, IdentityProviderUnavailable
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
        leeway: float = 0,
        required_claims: tuple[str, ...] = ("exp", "iat", "sub"),
        expected_typ: str | None = None,
        allowed_azp: tuple[str, ...] | None = None,
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

            leeway (float):
                Clock-skew tolerance, in seconds, applied to `exp`/`nbf`/
                `iat` validation (passed straight through to `jwt.decode`).
                PyJWT's own default is `0` — no tolerance at all — which
                means any real clock drift between this service and the
                IdP produces intermittent, hard-to-diagnose token
                rejections right at expiry boundaries (see DX2-9). Left at
                `0` here too, since the right value is deployment-specific;
                set it explicitly (e.g. `30`) once you've measured your
                actual clock drift.

            required_claims (tuple[str, ...]):
                Claims a token must carry (SEC3-8). PyJWT only validates
                `exp`/`iat`/`nbf` *if present* — a signed token with no
                `exp` used to be accepted forever. `iss`/`aud` are always
                enforced on top of this.

            expected_typ (Optional[str]):
                If set, the token's `typ` claim must equal it
                (case-insensitive). Keycloak marks access tokens `Bearer`
                and ID tokens `ID` — set `"Bearer"` so an ID token (whose
                `aud` is the client id, and so may match `audience`)
                can't be replayed as an access token. Leave unset for
                providers that don't emit `typ` (e.g. Auth0).

            allowed_azp (Optional[tuple[str, ...]]):
                If set, the token's `azp` (authorized party — the client
                it was issued to) must be one of these. Use it to accept
                only tokens minted for your own client, not ones a
                different client of the same realm obtained.
        """
        self.issuer = issuer.rstrip("/")
        self.audience = audience
        self.leeway = leeway
        self.required_claims = tuple(required_claims)
        self.expected_typ = expected_typ
        self.allowed_azp = tuple(allowed_azp) if allowed_azp is not None else None

        self._explicit_jwks_url = jwks_url
        self._discovery: dict[str, Any] | None = None

        self._jwks: dict[str, Any] | None = None
        self._jwks_refresh_cooldown = jwks_refresh_cooldown
        self._last_refresh_at: float | None = None

        # Guards the cold-start (and post-key-rotation forced-refresh)
        # JWKS fetch: without it, N concurrent `validate()` calls that all
        # observe `self._jwks is None` (e.g. at process startup, or right
        # after every cached key is invalidated by a rotation) each fire
        # their own `_fetch_jwks()` against the IdP instead of one caller
        # fetching and the rest reusing the result — a thundering herd.
        # Mirrors `MultiTenantAuthz._resolution_lock`'s check-then-act
        # double-checked-locking shape in `api.py`.
        self._jwks_lock = asyncio.Lock()

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
            try:
                async with httpx.AsyncClient() as client:
                    res = await client.get(f"{self.issuer}/.well-known/openid-configuration")
                    res.raise_for_status()
                    self._discovery = res.json()
            except httpx.HTTPError as exc:
                # A network error, timeout, or non-2xx response fetching
                # the discovery document — the IdP dependency itself is
                # unreachable, not "this token is invalid". Previously
                # propagated as a raw httpx exception, crashing every
                # authenticated request with an unhandled 500 for as long
                # as the IdP was down (see ARCH2-7).
                raise IdentityProviderUnavailable(
                    f"Unable to fetch OIDC discovery document from {self.issuer}",
                    service="oidc",
                    cause=exc,
                ) from exc

        return self._discovery["jwks_uri"]

    async def _fetch_jwks(self) -> dict[str, Any]:
        jwks_url = await self._resolve_jwks_url()
        try:
            async with httpx.AsyncClient() as client:
                res = await client.get(jwks_url)
                res.raise_for_status()
                return res.json()
        except httpx.HTTPError as exc:
            raise IdentityProviderUnavailable(
                f"Unable to fetch JWKS from {jwks_url}",
                service="oidc",
                cause=exc,
            ) from exc

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

        Concurrent callers that would otherwise each trigger their own
        fetch (cold start, or right after a rotation invalidates the
        cache) are serialized behind `_jwks_lock` instead — see DX2-9's
        thundering-herd fix. The cheap "anything to do at all" check
        happens once before taking the lock so a cache *hit* (the
        overwhelmingly common case) never pays for it.
        """
        if not force_refresh and self._jwks is not None:
            return self._jwks

        async with self._jwks_lock:
            if not force_refresh:
                # Re-check: another caller may have finished the exact
                # fetch this one was about to make while we were waiting
                # for the lock.
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
            kid = unverified_header.get("kid")

            if kid is None:
                # A JWT with no `kid` header (valid per spec — the header
                # is optional there — or trivially crafted by an
                # attacker) used to raise a bare, uncaught `KeyError`
                # here, escaping as an unhandled 500 through
                # `KeycloakAuthMiddleware` (which only catches
                # `AuthenticationError`) instead of a clean 401 (see
                # DX2-5).
                raise AuthenticationError("Invalid token: missing kid")

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
                # `from_jwk`'s stub return type is broader (`RSAPrivateKey
                # | RSAPublicKey`) than what `jwt.decode` accepts for
                # verification, because the JWK *format* can encode
                # either — but a JWKS endpoint only ever publishes public
                # keys, so this is always actually an `RSAPublicKey` in
                # practice (see DX2-2).
                public_key,  # type: ignore[arg-type]
                algorithms=self.ALGORITHMS,
                audience=self.audience,
                issuer=self.issuer,
                leeway=self.leeway,
                options={"require": list(self.required_claims)},
            )

            self._check_typ_and_azp(payload)
            return payload

        except jwt.ExpiredSignatureError as e:
            raise AuthenticationError("Token expired") from e

        except jwt.InvalidAudienceError as e:
            raise AuthenticationError(self._audience_error_message(e)) from e

        except jwt.InvalidTokenError as e:
            raise AuthenticationError(f"Invalid token: {str(e)}") from e

    def _check_typ_and_azp(self, payload: dict[str, Any]) -> None:
        if self.expected_typ is not None:
            typ = payload.get("typ")
            if not isinstance(typ, str) or typ.lower() != self.expected_typ.lower():
                raise AuthenticationError(
                    f"Invalid token: expected typ {self.expected_typ!r}, got {typ!r}"
                )
        if self.allowed_azp is not None and payload.get("azp") not in self.allowed_azp:
            raise AuthenticationError(
                "Invalid token: issued to a client this service doesn't accept"
            )

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
        Convert JWT payload → Identity.

        `attributes` carries the full decoded token payload — this is
        what lets a caller build a tenant resolver (or any other
        claim-based decision) off a *verified* claim (e.g. a custom
        `tenant_id`/`org_id` claim the IdP was configured to issue)
        instead of trusting unauthenticated request data like a header.
        See `adapters/fastapi.py:tenant_from_verified_claim` and SEC2-2.
        """
        sub = payload.get("sub")

        if not sub:
            raise AuthenticationError("Missing 'sub' in token")

        return Identity(id=f"user:{sub}", attributes=payload)

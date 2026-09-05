from py_authz.adapters.oidc import OIDCJWTValidator


class KeycloakJWTValidator(OIDCJWTValidator):
    """
    Validates and decodes JWT tokens issued by Keycloak.

    A thin `OIDCJWTValidator` subclass: Keycloak's JWKS endpoint is at a
    deterministic path (`{issuer}/protocol/openid-connect/certs`), so this
    passes it explicitly and skips the OIDC-discovery round trip
    `OIDCJWTValidator` otherwise makes on first use. Everything else
    (JWKS caching + rate-limited refetch-on-unknown-kid, signature
    verification, exception mapping) is inherited unchanged.

    Features:
        - Fetches JWKS (public keys)
        - Verifies signature
        - Extracts user identity
    """

    def __init__(
        self,
        issuer: str,
        audience: str,
        *,
        jwks_refresh_cooldown: float = 60.0,
        leeway: float = 0,
    ):
        """
        Args:
            issuer (str):
                Keycloak issuer URL
                e.g. https://auth.example.com/realms/myrealm

            audience (str):
                Expected audience (client_id)

            jwks_refresh_cooldown (float):
                Minimum seconds between forced JWKS refetches — see
                `OIDCJWTValidator._get_jwks`.

            leeway (float):
                Clock-skew tolerance, in seconds, for `exp`/`nbf`/`iat`
                validation — see `OIDCJWTValidator.__init__` (DX2-9).
        """
        issuer = issuer.rstrip("/")
        super().__init__(
            issuer,
            audience,
            jwks_url=f"{issuer}/protocol/openid-connect/certs",
            jwks_refresh_cooldown=jwks_refresh_cooldown,
            leeway=leeway,
        )
        # Preserved as a plain attribute (rather than only living inside
        # the base class's `_explicit_jwks_url`) since it was public API
        # before this class delegated to `OIDCJWTValidator`.
        self.jwks_url = self._explicit_jwks_url

    def _audience_error_message(self, exc: Exception) -> str:
        """
        Keycloak-specific hint: access tokens default to `aud: "account"`
        unless an audience mapper is added to the client — a well-known
        first-integration gotcha with no signal from Keycloak itself.
        """
        return (
            f"Invalid token: audience mismatch — the token's 'aud' claim "
            f"does not include {self.audience!r}. Keycloak access tokens "
            f'default to aud: "account" unless you add an audience '
            f"mapper to the client (Client scopes → dedicated scope → "
            f"Mappers → Audience, mapped to this client's ID) or set the "
            f'client scope\'s "included client audience". See '
            f"`docker/keycloak/realm.json`'s `oidc-audience-mapper` for a "
            f"working example."
        )

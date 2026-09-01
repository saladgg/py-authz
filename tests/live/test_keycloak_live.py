"""
Real Keycloak JWT validation, end to end.

Every other Keycloak test in the suite (`tests/adapters/test_keycloak.py`)
stubs or monkeypatches PyJWT/httpx entirely. This fetches a real token from
a real Keycloak realm via the direct-grant (Resource Owner Password)
flow and validates it through the unmodified `KeycloakJWTValidator` —
matching the credentials seeded by `docker/keycloak/realm.json`: client
`py-authz-demo`, user `alice`/`alice`.
"""

import os

import httpx
import pytest

from py_authz.adapters.keycloak import KeycloakJWTValidator
from py_authz.adapters.oidc import OIDCJWTValidator
from py_authz.core.exceptions import AuthenticationError

from .conftest import KEYCLOAK_AUDIENCE, KEYCLOAK_ISSUER, requires_keycloak

KEYCLOAK_TEST_USER = os.environ.get("KEYCLOAK_TEST_USER", "alice")
KEYCLOAK_TEST_PASSWORD = os.environ.get("KEYCLOAK_TEST_PASSWORD", "alice")


async def _fetch_token() -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post(
            f"{KEYCLOAK_ISSUER}/protocol/openid-connect/token",
            data={
                "grant_type": "password",
                "client_id": KEYCLOAK_AUDIENCE,
                "username": KEYCLOAK_TEST_USER,
                "password": KEYCLOAK_TEST_PASSWORD,
            },
        )
        response.raise_for_status()
        return response.json()["access_token"]


@requires_keycloak
@pytest.mark.asyncio
async def test_validate_accepts_a_real_keycloak_token():
    token = await _fetch_token()

    validator = KeycloakJWTValidator(issuer=KEYCLOAK_ISSUER, audience=KEYCLOAK_AUDIENCE)

    payload = await validator.validate(token)
    identity = validator.to_identity(payload)

    assert payload["preferred_username"] == KEYCLOAK_TEST_USER
    assert identity.id.startswith("user:")


@requires_keycloak
@pytest.mark.asyncio
async def test_validate_rejects_wrong_audience():
    token = await _fetch_token()

    validator = KeycloakJWTValidator(issuer=KEYCLOAK_ISSUER, audience="not-the-real-client")

    with pytest.raises(AuthenticationError):
        await validator.validate(token)


@requires_keycloak
@pytest.mark.asyncio
async def test_generic_oidc_validator_resolves_keycloak_via_discovery():
    """
    Regression test for SEC-2: the plain `OIDCJWTValidator` (no explicit
    `jwks_url`, unlike `KeycloakJWTValidator`) must resolve Keycloak's
    JWKS endpoint via real OIDC discovery
    (`{issuer}/.well-known/openid-configuration`) and validate a real
    token — proving the generic, non-Keycloak-specific path actually
    works against a real, standards-compliant provider, not just a mock.
    """
    token = await _fetch_token()

    validator = OIDCJWTValidator(issuer=KEYCLOAK_ISSUER, audience=KEYCLOAK_AUDIENCE)

    payload = await validator.validate(token)

    assert payload["preferred_username"] == KEYCLOAK_TEST_USER

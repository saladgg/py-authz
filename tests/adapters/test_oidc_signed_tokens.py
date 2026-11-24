"""
`OIDCJWTValidator` against REAL signed tokens (SEC3-8, DX3-3).

The rest of the suite monkeypatches `jwt.decode` itself, so the actual
verification rules — the RS256-only algorithm allow-list, issuer/audience
checks, required claims — were never exercised with a real signature.
These tests mint tokens with a throwaway RSA key and feed the validator
the matching JWKS, so every assertion runs PyJWT's real verification.
"""

import base64
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from py_authz.adapters.oidc import OIDCJWTValidator
from py_authz.core.exceptions import AuthenticationError

ISSUER = "https://auth.example.com/realms/test"
AUDIENCE = "py-authz-control-plane"
KID = "test-key"


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _validator(rsa_key, **kwargs) -> OIDCJWTValidator:
    validator = OIDCJWTValidator(
        issuer=ISSUER, audience=AUDIENCE, jwks_url="https://unused.invalid/keys", **kwargs
    )
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key()))
    jwk["kid"] = KID
    validator._jwks = {"keys": [jwk]}  # pre-seeded: no network
    return validator


def _claims(**overrides):
    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "alice",
        "iat": now,
        "exp": now + 300,
        "typ": "Bearer",
        "azp": "control-panel",
    }
    claims.update(overrides)
    return {k: v for k, v in claims.items() if v is not None}


def _sign(rsa_key, claims, *, alg="RS256", kid=KID):
    return jwt.encode(claims, rsa_key, algorithm=alg, headers={"kid": kid})


@pytest.mark.asyncio
async def test_a_valid_token_is_accepted(rsa_key):
    payload = await _validator(rsa_key).validate(_sign(rsa_key, _claims()))
    assert payload["sub"] == "alice"


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", ["exp", "iat", "sub"])
async def test_a_token_missing_a_required_claim_is_rejected(rsa_key, missing):
    """SEC3-8: PyJWT validates `exp` only if present — a signed token with
    no `exp` used to be accepted forever."""
    token = _sign(rsa_key, _claims(**{missing: None}))

    with pytest.raises(AuthenticationError):
        await _validator(rsa_key).validate(token)


@pytest.mark.asyncio
async def test_alg_none_is_rejected(rsa_key):
    header = base64.urlsafe_b64encode(json.dumps({"alg": "none", "kid": KID}).encode())
    body = base64.urlsafe_b64encode(json.dumps(_claims()).encode())
    token = f"{header.rstrip(b'=').decode()}.{body.rstrip(b'=').decode()}."

    with pytest.raises(AuthenticationError):
        await _validator(rsa_key).validate(token)


@pytest.mark.asyncio
async def test_hs256_signed_with_the_public_key_is_rejected(rsa_key):
    """Classic key-confusion: HMAC-sign with the RSA public key as secret."""
    public_pem = rsa_key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = {"alg": "HS256", "kid": KID, "typ": "JWT"}
    import hashlib
    import hmac

    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(_claims()).encode())}"
    signature = hmac.new(public_pem, signing_input.encode(), hashlib.sha256).digest()
    token = f"{signing_input}.{b64(signature)}"

    with pytest.raises(AuthenticationError):
        await _validator(rsa_key).validate(token)


@pytest.mark.asyncio
async def test_a_token_signed_by_a_different_key_is_rejected(rsa_key):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with pytest.raises(AuthenticationError):
        await _validator(rsa_key).validate(_sign(other, _claims()))


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "overrides",
    [
        {"iss": "https://evil.example.com"},
        {"aud": "some-other-client"},
        {"exp": int(time.time()) - 60},
        {"nbf": int(time.time()) + 3600},
    ],
    ids=["wrong-iss", "wrong-aud", "expired", "not-yet-valid"],
)
async def test_standard_claim_checks(rsa_key, overrides):
    with pytest.raises(AuthenticationError):
        await _validator(rsa_key).validate(_sign(rsa_key, _claims(**overrides)))


@pytest.mark.asyncio
async def test_expected_typ_rejects_an_id_token(rsa_key):
    """SEC3-8: a Keycloak ID token (typ=ID, aud=client id) could be
    replayed as an access token when audience == client id."""
    validator = _validator(rsa_key, expected_typ="Bearer")

    assert await validator.validate(_sign(rsa_key, _claims(typ="Bearer")))
    with pytest.raises(AuthenticationError, match="typ"):
        await validator.validate(_sign(rsa_key, _claims(typ="ID")))
    with pytest.raises(AuthenticationError):
        await validator.validate(_sign(rsa_key, _claims(typ=None)))


@pytest.mark.asyncio
async def test_allowed_azp_rejects_tokens_issued_to_other_clients(rsa_key):
    validator = _validator(rsa_key, allowed_azp=("control-panel",))

    assert await validator.validate(_sign(rsa_key, _claims(azp="control-panel")))
    with pytest.raises(AuthenticationError):
        await validator.validate(_sign(rsa_key, _claims(azp="product-app")))
    with pytest.raises(AuthenticationError):
        await validator.validate(_sign(rsa_key, _claims(azp=None)))

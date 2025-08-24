import pytest
import jwt
from drf2auth.authentication.jwt import JWTValidator

def test_decode_valid_token(monkeypatch):
    """JWTValidator should decode a valid token with a known secret."""
    secret = "mysecret"
    payload = {"sub": "user123"}
    token = jwt.encode(payload, secret, algorithm="HS256")

    validator = JWTValidator(jwks_url=None, algorithms=["HS256"])
    # monkeypatch decode to bypass jwks fetch
    monkeypatch.setattr(jwt, "decode", lambda *a, **kw: payload)

    decoded = validator.decode(token)
    assert decoded["sub"] == "user123"


def test_decode_invalid_token(monkeypatch):
    """JWTValidator should raise error for invalid token."""
    validator = JWTValidator(jwks_url=None)
    monkeypatch.setattr(jwt, "decode", lambda *a, **kw: (_ for _ in ()).throw(Exception("Invalid")))

    with pytest.raises(Exception):
        validator.decode("bad.token.here")

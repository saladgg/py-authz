# Configuration

Configure via `settings.DJANGO_AUTHZ` or environment variables prefixed `DJANGO_AUTHZ_`.

```python
DJANGO_AUTHZ = {
    "KEYCLOAK_URL": "https://keycloak.example.com",
    "KEYCLOAK_REALM": "myrealm",
    "KEYCLOAK_CLIENT_ID": "backend",
    "KEYCLOAK_CLIENT_SECRET": "***",
    "OPENFGA_API_URL": "https://api.openfga.example.com",
    "OPENFGA_STORE_ID": "01H...",
    "OPENFGA_MODEL_ID": "01H...",    # optional — pin to a specific model
    "OPENFGA_AUTH_TOKEN": "***",     # optional — bearer for FGA management API
    "VERIFY_JWT": True,              # set False in development only
    "JWKS_URL": None,                # inferred from KEYCLOAK_URL/REALM if unset
    "EXPECTED_AUDIENCE": None,       # recommended in production
    "EXPECTED_ISSUER": None,         # recommended in production
    "JWT_LEEWAY": 60,                # seconds of clock-skew tolerance
}
```

| Key | Description |
|-----|-------------|
| `KEYCLOAK_URL` | Base URL to Keycloak |
| `KEYCLOAK_REALM` | Realm name |
| `KEYCLOAK_CLIENT_ID` | Client ID |
| `KEYCLOAK_CLIENT_SECRET` | Client secret (optional for public clients) |
| `VERIFY_JWT` | Enable/disable JWT signature verification (default: `True`) |
| `JWKS_URL` | JWKS endpoint; inferred from `KEYCLOAK_URL`/`KEYCLOAK_REALM` if unset |
| `EXPECTED_AUDIENCE` | Expected `aud` claim value |
| `EXPECTED_ISSUER` | Expected `iss` claim value |
| `JWT_LEEWAY` | Clock-skew tolerance in seconds (default: 60) |
| `OPENFGA_API_URL` | OpenFGA API base URL |
| `OPENFGA_STORE_ID` | OpenFGA store ID |
| `OPENFGA_MODEL_ID` | Optional — pin checks to a specific authorization model |
| `OPENFGA_AUTH_TOKEN` | Optional — bearer token for the FGA management API |

# drf-authz

**Keycloak + OpenFGA for Django REST Framework**, in one reusable library.

## Features
- Plug-and-play authentication via **Keycloak (OIDC)** or **JWT**
- Fine-grained authorization via **OpenFGA** (relation tuples & checks)
- Clean, testable abstractions & DRF permission classes

## Quickstart

```bash
pip install drf-authz
```

Add to `INSTALLED_APPS` and middleware:

```python
INSTALLED_APPS += ["drf-authz"]
MIDDLEWARE += ["drf-authz.middleware.request_context.RequestContextMiddleware"]
```

Configure (env or Django settings):

```python
DRF-AUTHz = {
  "KEYCLOAK_URL": "https://keycloak.example.com",
  "KEYCLOAK_REALM": "myrealm",
  "KEYCLOAK_CLIENT_ID": "backend",
  "KEYCLOAK_CLIENT_SECRET": "***",
  "OPENFGA_API_URL": "https://api.openfga.example.com",
  "OPENFGA_STORE_ID": "01H...",
  "OPENFGA_MODEL_ID": "01H...",  # optional
  "OPENFGA_AUTH_TOKEN": "***",    # optional bearer for FGA API
}
```



## TODO:

- how to package (clearly document this) ---> also read what you already have
- ask about versioning ()
- Step by step simple demo from django project creation

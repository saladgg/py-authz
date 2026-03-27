## Layout

django-authz/
├── pyproject.toml
├── README.md
├── LICENCE
├── Makefile
├── uv.lock
├── docs/
│   ├── index.md
│   ├── getting_started.md
│   ├── configuration.md
│   └── api_reference.md
├── django_authz/               ← Python package (import path)
│   ├── __init__.py
│   ├── apps.py
│   ├── conf.py                 # Centralised, typed settings (DJANGO_AUTHZ / env vars)
│   ├── exceptions.py           # DjangoAuthzError hierarchy
│   ├── utils.py                # get_bearer_token, merge_dicts
│   ├── permissions.py          # FGAPermissionMixin (CBV)
│   ├── authentication/
│   │   ├── __init__.py
│   │   ├── backends.py         # get_or_create_user provisioning helper
│   │   ├── jwt.py              # JWTAuthenticationBackend (JWKS / PyJWT)
│   │   ├── keycloak.py         # KeycloakAdmin wrapper (python-keycloak)
│   │   └── oidc.py             # OIDCAuthenticationBackend (mozilla-django-oidc)
│   ├── authorization/
│   │   ├── __init__.py
│   │   ├── base.py             # BaseOpenFGAClient abstract interface
│   │   ├── openfga.py          # REST client (requests)
│   │   ├── openfga_sdk.py      # SDK client (openfga-sdk, async + sync wrapper)
│   │   ├── decorators.py       # @fga_requires view decorator
│   │   └── policies.py         # Policy high-level helper
│   ├── middleware/
│   │   ├── __init__.py
│   │   └── request_context.py  # RequestContextMiddleware (user, context, request_id)
│   ├── models/
│   │   ├── __init__.py
│   │   ├── tokens.py           # Principal, IDToken, AccessToken dataclasses
│   │   └── relations.py        # RelationTuple dataclass + fga_string()
│   └── management/commands/
│       ├── __init__.py
│       └── sync_openfga.py     # `manage.py sync_openfga`
├── tests/
│   ├── __init__.py
│   ├── settings.py             # Minimal Django settings for pytest
│   ├── conftest.py
│   ├── test_authentication.py
│   ├── test_authorization.py
│   ├── test_permissions.py
│   └── test_middleware.py
└── demo_project/               # Minimal Django app showcasing usage
    ├── manage.py
    ├── demo_project/
    │   ├── settings.py
    │   ├── urls.py
    │   └── wsgi.py
    └── api/
        ├── permissions.py
        ├── view_1.py
        ├── view_2.py
        └── urls.py


## Key Components

`authentication/`
- Pluggable backends: JWT (JWKS), OIDC (mozilla-django-oidc), Keycloak admin.
- `JWTAuthenticationBackend` is a standard Django `ModelBackend`; attach to
  `AUTHENTICATION_BACKENDS` — no DRF dependency.

`authorization/`
- `BaseOpenFGAClient` defines `check / write / list_relations`.
- `OpenFGAClient` — lightweight REST client via `requests`; no async dep.
- `OpenFGASDKClient` — official `openfga-sdk` (async); sync wrapper uses
  `asyncio.run()` for standard views.  Use `AsyncOpenFGASDKClient` directly
  for ASGI / async views.

`permissions/`
- `FGAPermissionMixin` works with any Django CBV detail view (no DRF).
- `@fga_requires` for function/method-based views.

`middleware/`
- `RequestContextMiddleware` guarantees `request.user` and `request.context`
  (with `request_id` UUID) are always present.

`models/`
- Pure dataclasses — no ORM models.  Lightweight, immutable, testable.

`management/commands/`
- `sync_openfga` is a placeholder; replace the example tuple with your own
  policy registry.


## OpenFGAClient vs OpenFGASDKClient

| | `OpenFGAClient` | `OpenFGASDKClient` |
|---|---|---|
| Transport | `requests` (sync) | `openfga-sdk` (async) |
| Extra dep | `requests` (already a Django dep) | `openfga-sdk` |
| Async views | ✗ | ✓ (`AsyncOpenFGASDKClient`) |
| Swap cost | Drop-in (same `BaseOpenFGAClient`) | Drop-in |

Both satisfy `BaseOpenFGAClient.check()`, so `FGAPermissionMixin` and
`@fga_requires` don't care which you use.


## Version handling

`__init__.py` reads the installed distribution version via
`importlib.metadata.version("django-authz")`.  Falls back to `"0.0.0"` in
editable/dev installs where metadata may not yet exist.


## Dependency philosophy

This is a library, not an application.

- Declare minimum compatible versions, not exact pins.
- Optional integrations (Keycloak admin, OIDC) are always-declared but each
  sub-package guards its own imports — apps that don't use Keycloak don't pay
  the import cost.
- `Django>=4.2` covers the current LTS and Django 5.x.

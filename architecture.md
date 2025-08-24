## GPT while on sil account (https://chatgpt.com/c/68a8982d-04e8-8322-941c-c58637a653f1)

## Layout

drf-authz/
├── pyproject.toml
├── README.md
├── LICENSE
├── .gitignore
├── .editorconfig
├── .pre-commit-config.yaml
├── docs/
│   ├── index.md
│   ├── getting_started.md
│   ├── configuration.md
│   └── api_reference.md
├── src/
│   └── drf_authz/
│       ├── __init__.py
│       ├── apps.py
│       ├── conf.py
│       ├── exceptions.py
│       ├── utils.py
│       ├── settings.py
│       ├── permissions.py
│       ├── authentication/
│       │   ├── __init__.py
│       │   ├── backends.py             # Django/DRF auth backends
│       │   ├── keycloak.py             # Keycloak-specific integration (python-keycloak)
│       │   ├── oidc.py                 # OIDC flows (mozilla-django)
│       │   └── jwt.py                  # JWT auth (drf-simplejwt)
│       ├── authorization/
│       │   ├── __init__.py
│       │   ├── openfga.py              # OpenFGA client wrapper  
│       │   ├── policies.py             # Policy abstractions
│       │   └── decorators.py           # DRF permission decorators
│       ├── middleware/
│       │   ├── __init__.py
│       │   └── request_context.py      # Attach auth info into request
│       ├── models/
│       │   ├── __init__.py
│       │   ├── tokens.py               # Dataclasses/attrs for token modeling
│       │   └── relations.py            # Dataclasses/attrs for OpenFGA tuples
│       └── management/
│           └── commands/
│               └── sync_openfga.py     # Example management command for syncing policies
└── demo_project
        ├── manage.py
        ├── demo_project/
        │   ├── __init__.py
        │   ├── settings.py
        │   ├── urls.py
        │   └── wsgi.py
        └── api/
            ├── __init__.py
            ├── view_1.py
            ├── view_2.py
            └── urls.py


## Key Components:

`authentication/`
- Houses Keycloak/OIDC/JWT logic. Each backend (Keycloak, OIDC, JWT) is pluggable and reusable.

`authorization/`
- Wraps the openfga-sdk, providing a clean API for checking relations, managing tuples, and defining policies.

`permissions/`
- DRF permission classes that connect authentication (user identity) to authorization (OpenFGA checks).

`middleware/`
- Middleware for attaching request context, e.g. request.auth, request.user, and optionally request.permissions.

`models/`
- Lightweight dataclasses/attrs objects for tokens, identities, and FGA relations (helps with testability & immutability).

`management/commands/`
- Django management command for syncing or validating policies against OpenFGA.

`tests/`
- Organized into unit (auth, authz, permissions) and integration (end-to-end with Keycloak & OpenFGA mocks).

`demo_project/`
- A minimal DRF project to showcase usage.

## ---------------------------------------------------------------
# ../authorization/openfga.py v/s ../authorization/openfga_sdk.py
## ---------------------------------------------------------------
`See how demo_project/api/permissions.py` can use ony of the two clients

- Both OpenFGASDKClient and OpenFGAClient implement the same interface (BaseOpenFGAClient),
  so FGAPermission doesn’t care which one you use.
- The FGAPermission class depends only on BaseOpenFGAClient.
- You can swap clients (OpenFGAClient vs OpenFGASDKClient) without touching your permission 
  classes — just wire in the client you prefer. This keeps things pluggable and clean.

**The only difference is:**

- OpenFGAClient → lightweight REST-based client (your lib’s own implementation, using requests).
- OpenFGASDKClient → official SDK-based client (from openfga-sdk).
- Both satisfy BaseOpenFGAClient.check(). So swapping them is a drop-in replacement.

# --------------------------------------------------
# Version handling
# --------------------------------------------------
`.../src/drf_authz/__init__.py`

- Using importlib.metadata.version("drf-authz") is good — it pulls the version from your installed 
  distribution metadata thus the string must match the distribution name on PyPI
- The except fallback to "0.0.0" is fine for dev/test environments where the package may not be installed yet.

`.../src/drf_authz/apps.py`
- name should always be the Python import path of your app → "drf_authz" is correct here.
- verbose_name is what shows up in the Django admin. You can make it human-friendly 

✅ 4. Best practices for dependencies in libraries

To make your library widely usable:

Pin loosely in the library
Use version ranges so you don’t block apps unnecessarily:
djangorestframework = ">=3.14,<4.0"
python-keycloak = ">=3.0,<4.0"

Leave Django itself optional
Many apps already pin Django.
You can either:

Declare django as a dependency with a range:
django = ">=4.2,<6.0"
Or leave it out, and document: “You must install Django yourself.”

Both are valid — depends on how opinionated your library is.

Optional dependencies (extras)
If your lib supports multiple backends, group them:
[project.optional-dependencies]
oidc = ["mozilla-django-oidc"]
jwt = ["djangorestframework-simplejwt"]
fga = ["openfga-sdk"]
Then apps can install:

pip install drf2auth[fga,jwt]

📌 5. The rule of thumb

Library = declare what’s needed for itself to run.

Application = declare everything it needs, including Django, Celery, DRF, etc.

Overlap is fine, as long as version ranges are compatible.


# django-authz

**Keycloak authentication + OpenFGA fine-grained authorization for Django.**

`django-authz` wires together two complementary security systems into one
reusable Django library:

- **Authentication** — validate Keycloak-issued JWTs, introspect tokens via
  OIDC, and optionally manage users through the Keycloak Admin API.
- **Authorization** — evaluate relation-based permissions against an
  [OpenFGA](https://openfga.dev) store using either a lightweight `requests`
  client or the official async `openfga-sdk`, with a CBV mixin and view
  decorator for drop-in enforcement.

---

## Table of contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Authentication](#authentication)
  - [JWT backend](#jwt-backend)
  - [OIDC backend](#oidc-backend)
  - [Keycloak admin](#keycloak-admin)
- [Authorization](#authorization)
  - [OpenFGA clients](#openfga-clients)
  - [Permission mixin (CBV)](#permission-mixin-cbv)
  - [View decorator](#view-decorator)
  - [Policy helper](#policy-helper)
  - [Management command](#management-command)
- [Configuration reference](#configuration-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Requirements

- Python ≥ 3.13
- Django ≥ 6.0
- A running [Keycloak](https://www.keycloak.org/) instance (authentication)
- A running [OpenFGA](https://openfga.dev/) instance (authorization)

---

## Installation

```bash
pip install django-authz
```

---

## Quick start

**1. Add to `INSTALLED_APPS` and `MIDDLEWARE`:**

```python
INSTALLED_APPS = [
    ...
    "django_authz",
]

MIDDLEWARE = [
    ...
    "django_authz.middleware.request_context.RequestContextMiddleware",
]
```

**2. Register the JWT authentication backend:**

```python
AUTHENTICATION_BACKENDS = [
    "django_authz.authentication.jwt.JWTAuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend",
]
```

**3. Configure the library (Django settings or environment variables):**

```python
DJANGO_AUTHZ = {
    # Keycloak
    "KEYCLOAK_URL": "https://keycloak.example.com",
    "KEYCLOAK_REALM": "myrealm",
    "KEYCLOAK_CLIENT_ID": "backend",
    "KEYCLOAK_CLIENT_SECRET": "secret",

    # OpenFGA
    "OPENFGA_API_URL": "https://api.openfga.example.com",
    "OPENFGA_STORE_ID": "01HXXX",
}
```

Every key can also be supplied as an environment variable prefixed with
`DJANGO_AUTHZ_` — e.g. `DJANGO_AUTHZ_OPENFGA_STORE_ID`.

---

## Authentication

### JWT backend

`JWTAuthenticationBackend` is a standard Django authentication backend. It
extracts the `Authorization: Bearer <token>` header, validates the JWT
signature against the Keycloak JWKS endpoint, and resolves (or creates) the
matching `User` object.

```python
AUTHENTICATION_BACKENDS = [
    "django_authz.authentication.jwt.JWTAuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend",
]
```

On a successful authentication the decoded claims are available on the request
as a `Principal` dataclass:

```python
def my_view(request):
    principal = request.jwt_principal
    print(principal.subject)   # JWT "sub" claim
    print(principal.email)     # JWT "email" claim
    print(principal.claims)    # full decoded payload
```

**JWKS URL** is inferred automatically from `KEYCLOAK_URL` / `KEYCLOAK_REALM`
(`/realms/{realm}/protocol/openid-connect/certs`). Override with `JWKS_URL`
if your setup differs.

**Signature verification** is enabled by default (`VERIFY_JWT=True`). Set
`VERIFY_JWT=False` only in development — it skips signature and audience
checks entirely.

### OIDC backend

For full OIDC code-flow authentication (e.g. server-side login), add
`mozilla-django-oidc` (already a dependency) and follow its
[documentation](https://mozilla-django-oidc.readthedocs.io/). `django-authz`
is compatible with its `OIDCAuthenticationBackend` out of the box.

### Keycloak admin

A thin `KeycloakAdmin` wrapper is available for management tasks such as
looking up users:

```python
from django_authz.authentication.keycloak import KeycloakAdmin

admin = KeycloakAdmin()
user_info = admin.get_user("user-uuid-here")
```

The `python-keycloak` client is configured automatically from the
`KEYCLOAK_*` settings.

---

## Authorization

### OpenFGA clients

Two client implementations are provided, both conforming to the same
`BaseOpenFGAClient` interface (`check`, `write`, `list_relations`).

#### Lightweight REST client (default)

Uses `requests` directly — zero async overhead, suitable for standard
synchronous Django views:

```python
from django_authz.authorization.openfga import OpenFGAClient

client = OpenFGAClient(api_url="http://localhost:8080", store_id="01HXXX")

# Check a permission
allowed = client.check(user="user:alice", relation="viewer", object_="document:readme")

# Write relation tuples
client.write([
    {"user": "user:alice", "relation": "editor", "object": "document:readme"},
])

# List all relations a user holds on an object
relations = client.list_relations(user="user:alice", object_="document:readme")
```

#### Official SDK client (sync + async)

Uses the [`openfga-sdk`](https://github.com/openfga/python-sdk) for full
feature parity with the OpenFGA API. Two variants are provided:

```python
from django_authz.authorization.openfga_sdk import OpenFGASDKClient, AsyncOpenFGASDKClient

# Synchronous (safe for standard Django views — uses asyncio.run internally)
client = OpenFGASDKClient(api_url="http://localhost:8080", store_id="01HXXX")
allowed = client.check(user="user:alice", relation="viewer", object_="document:readme")

# Native async (for ASGI deployments / Django async views)
async_client = AsyncOpenFGASDKClient(api_url="http://localhost:8080", store_id="01HXXX")
allowed = await async_client.check(user="user:alice", relation="viewer", object_="document:readme")
```

Pass `model_id` to pin a specific authorization model version:

```python
client = OpenFGASDKClient(
    api_url="http://localhost:8080",
    store_id="01HXXX",
    model_id="01HYYY",
)
```

### Permission mixin (CBV)

`FGAPermissionMixin` enforces an OpenFGA check on any Django class-based
detail view. It calls `get_object()` to resolve the target object, then
verifies that the current user holds the specified relation on it.

```python
from django.views.generic import DetailView
from django_authz.permissions import FGAPermissionMixin
from django_authz.authorization.openfga import OpenFGAClient

fga_client = OpenFGAClient(api_url="http://localhost:8080", store_id="01HXXX")

class DocumentDetail(FGAPermissionMixin, DetailView):
    model = Document
    fga_client = fga_client
    fga_relation = "viewer"
```

The FGA user string defaults to `str(request.user)`. Override `get_fga_user()`
to customise it — for example to use a claim from `request.jwt_principal`:

```python
class DocumentDetail(FGAPermissionMixin, DetailView):
    model = Document
    fga_client = fga_client
    fga_relation = "viewer"

    def get_fga_user(self) -> str:
        return f"user:{self.request.jwt_principal.subject}"
```

Unauthorized requests are handled by `AccessMixin.handle_no_permission()`
(redirects to login or raises 403 depending on your `raise_exception` setting).

### View decorator

`@fga_requires` enforces a permission check on a class-based view method:

```python
from django_authz.authorization.decorators import fga_requires

class ProjectView(View):
    @fga_requires(object_type="project", relation="editor")
    def post(self, request, pk):
        # Only reachable if user holds "editor" on "project:{pk}"
        ...
```

Parameters:

| Parameter | Default | Description |
|---|---|---|
| `object_type` | — | FGA object type (e.g. `"project"`) |
| `relation` | — | Required relation (e.g. `"editor"`) |
| `object_id_kwarg` | `"pk"` | URL kwarg used as the object ID |
| `user_fmt` | `None` | `callable(request, *args, **kwargs) -> str`; defaults to `"user:{request.user.pk}"` |

The OpenFGA client is built from `OPENFGA_API_URL` / `OPENFGA_STORE_ID`
settings automatically.

### Policy helper

For imperative permission checks anywhere in application code:

```python
from django_authz.authorization.policies import Policy, ObjectRef

policy = Policy()   # uses OPENFGA_* settings automatically

if policy.is_allowed(user="user:alice", relation="admin", obj=ObjectRef(type="project", id="42")):
    ...
```

### Management command

Sync predefined policy tuples into your OpenFGA store:

```bash
python manage.py sync_openfga
```

The command ships with a placeholder implementation — extend
`django_authz/management/commands/sync_openfga.py` to register your own
policy tuples.

---

## Configuration reference

All settings live under the `DJANGO_AUTHZ` dict in Django settings, or as
`DJANGO_AUTHZ_<KEY>` environment variables.

| Key | Default | Description |
|---|---|---|
| `KEYCLOAK_URL` | `None` | Keycloak base URL (e.g. `https://keycloak.example.com`) |
| `KEYCLOAK_REALM` | `None` | Realm name |
| `KEYCLOAK_CLIENT_ID` | `None` | Client ID |
| `KEYCLOAK_CLIENT_SECRET` | `None` | Client secret |
| `VERIFY_JWT` | `True` | Enable JWT signature verification. Set `False` only in development. |
| `JWKS_URL` | `None` | Override JWKS endpoint. Inferred from Keycloak settings if omitted. |
| `EXPECTED_AUDIENCE` | `None` | Required JWT `aud` claim. Omit to skip audience validation. |
| `EXPECTED_ISSUER` | `None` | Required JWT `iss` claim. Omit to skip issuer validation. |
| `JWT_LEEWAY` | `60` | Clock-skew tolerance in seconds. |
| `OPENFGA_API_URL` | `None` | OpenFGA API base URL |
| `OPENFGA_STORE_ID` | `None` | OpenFGA store ID |
| `OPENFGA_MODEL_ID` | `None` | Pin a specific authorization model ID (optional) |
| `OPENFGA_AUTH_TOKEN` | `None` | Bearer token for the OpenFGA API (optional) |

---





## Contributing

1. Fork the repository and create a feature branch.
2. Install dev dependencies: `pip install -e ".[dev]"` (or with uv: `uv sync --group dev`).
3. Run the test suite: `pytest`.
4. Submit a pull request against `main`.

Please follow the existing code style (`ruff` is enforced via pre-commit).

---

## License

MIT — see [LICENSE](LICENSE) for details.

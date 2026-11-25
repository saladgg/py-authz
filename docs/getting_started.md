# Getting Started

A linear walkthrough from a blank project to your first enforced authorization
decision. If you already have OpenFGA running and just want the shortest
possible snippet, see the [Quickstart in the root README](../README.md#quickstart).

---

## 1. Install

Requires **Python 3.13+**.

```bash
# Core only
pip install py-authz

# Or with the extras you plan to use
pip install "py-authz[fastapi,redis,postgres,cli]"
# or everything:
pip install "py-authz[all]"
```

Using [`uv`](https://github.com/astral-sh/uv) for development:

```bash
make venv          # .venv with Python 3.13
make install-dev
```

The core has minimal dependencies (`httpx`, `attrs`, `anyio`). Everything
else — FastAPI, Redis, Postgres, Keycloak JWT — is an optional extra and is
loaded lazily with a helpful `ImportError` message if missing.

---

## 2. Start OpenFGA

py-authz is a client for [OpenFGA](https://openfga.dev); you need a running
instance. A dev compose file is bundled in the repo:

```bash
docker compose up -d openfga
curl http://localhost:8082/healthz
```

> The compose service uses OpenFGA's in-memory datastore, so it loses all data
> on container restart. For persistence, configure a Postgres-backed OpenFGA
> instance (outside the scope of this doc).

---

## 3. Define a model

Describe your resources and the relations users can hold on them. Each
`ResourceModel` subclass becomes one OpenFGA object type; each `Relation`
becomes one relation on that type.

```python
# myapp/authz/models.py
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry


class Document(ResourceModel):
    type = "document"

    owner = Relation("owner")
    editor = Relation("editor", union=["owner"])  # owner implies editor
    viewer = Relation("viewer", union=["editor"])  # editor implies viewer


registry.register(Document)
```

`union=[...]` is the simplest form of inheritance: "owner implies editor"
means anyone who holds `owner` *on this same object* automatically
satisfies an `editor` check too (OpenFGA's `computedUserset`).
`inherits=[...]` is currently just an alias of `union` — same shape, same
rewrite — kept only for backward compatibility with older models; don't
reach for it to mean "inherit from a *different*, parent object".

For that cross-object case — e.g. a document inheriting its folder's
viewers — use `from_parent=(tupleset_relation, computed_relation)`
instead (OpenFGA's `tupleToUserset`):

```python
class Folder(ResourceModel):
    type = "folder"
    viewer = Relation("viewer")


class Document(ResourceModel):
    type = "document"

    # Which folder this document lives in (populated by writing a tuple
    # with the folder as `user` and the document as `object`).
    parent = Relation("parent", subjects=["folder"])

    # A viewer of the parent folder is a viewer of this document too.
    viewer = Relation(
        "viewer",
        from_parent=("parent", "viewer"),
        subjects=["user"],  # from_parent alone defaults subjects to []
    )
```

See [`examples/11_hierarchical_permissions.py`](../examples/11_hierarchical_permissions.py)
for a complete, runnable version of this. `subjects=[...]` (default
`["user"]`, or `[]` when `from_parent` is set with no explicit `subjects`
— a purely-inherited relation isn't directly assignable by default)
declares which subject types can hold the relation directly.

You must call `registry.register(Cls)` on every model — the metaclass only
binds relation names to the class; it doesn't register the class itself.

---

## 4. Sync the model to OpenFGA

Uploading the model is a one-time operation per version. `ModelSync.sync`
diffs the local model against whatever is already in OpenFGA and uploads
only when something changed — so it's safe to run on every deploy.

```python
import os
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.model_sync import ModelSync
from myapp.authz import models  # noqa: F401 — registers models


async def bootstrap():
    client = OpenFGAClient(
        api_url=os.environ["FGA_API_URL"],  # http://localhost:8082
        store_id=None,  # we'll create one
        model_id=None,
    )
    try:
        store_id = await client.create_store("myapp")
        client.store_id = store_id

        syncer = ModelSync(client)
        model_id = await syncer.sync(force=True)
    finally:
        await client.aclose()

    print(f"Export: FGA_STORE_ID={store_id} FGA_MODEL_ID={model_id}")
```

Persist `store_id` (and optionally `model_id`) somewhere your app can read at
startup. The [examples](../examples/) have a `seed.py` that does exactly this
and also writes demo tuples so you can try the other scripts.

---

## 5. Grant some permissions

Tuples are the rows in OpenFGA that say "`alice` has the `owner` relation on
`document:roadmap`". Use the high-level `Authz.grant` API — no raw HTTP needed.

```python
from py_authz import Authz, Identity
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from myapp.authz.models import Document


client = OpenFGAClient(
    api_url=os.environ["FGA_API_URL"],
    store_id=os.environ["FGA_STORE_ID"],
    model_id=os.environ["FGA_MODEL_ID"],
)
authz = Authz(AuthzEngine(fga_client=client))

alice = Identity(id="user:alice")
roadmap = Document(id="roadmap")

await authz.grant(alice, "owner", roadmap)
# Or in bulk:
# await authz.grant_many([(alice, "owner", roadmap), (bob, "editor", roadmap)])
```

---

## 6. Enforce a check

Three flavors, pick the one that fits the call site:

```python
# Boolean — good for conditional UI logic
ok = await authz.enforce("editor", alice, roadmap.to_resource())

# Typed — prevents typos, IDE autocompletes relation names
ok = await authz.can(Document.editor, alice, roadmap)

# Raise-on-deny — good for service code where denial short-circuits execution
await authz.require("viewer", alice, roadmap.to_resource())
# -> raises AuthorizationDenied if not allowed
```

`require` raises `py_authz.core.exceptions.AuthorizationDenied`, a subclass
of `AuthzError`. Catch `AuthzError` at framework boundaries if you want one
net for every authorization failure.

---

## 7. Next steps

- **FastAPI** — protect routes declaratively with `require_fastapi` or
  `require_dependency`. See the [FastAPI section of the README](../README.md#fastapi-integration)
  and [`examples/04_fastapi_app.py`](../examples/04_fastapi_app.py).
- **Keycloak** — plug `KeycloakAuthMiddleware` in front of your app and every
  request gets an `Identity` on `request.state.user`. See
  [`examples/05_keycloak_fastapi.py`](../examples/05_keycloak_fastapi.py).
- **Caching** — pass an `InMemoryCache` or `RedisCache` to the engine.
  Cache keys are deterministic (`<user>:<action>:<type>:<id>`) so invalidation
  is straightforward. See [`examples/03_caching.py`](../examples/03_caching.py).
- **Multi-tenant** — use `MultiTenantAuthz` to isolate stores per tenant with
  optional auto-provisioning. See [`examples/06_multitenant.py`](../examples/06_multitenant.py).
- **Explain / bulk** — `AuthzEngine.explain` returns the decision plus, when allowed, the
  relation path that grants it (built from OpenFGA `/expand`);
  `AuthzEngine.bulk_enforce` checks N requests concurrently. See
  [`examples/07_explain_and_bulk.py`](../examples/07_explain_and_bulk.py).
- **Architecture** — read [`architecture.md`](architecture.md) for the
  request lifecycle and how each extension point plugs in.

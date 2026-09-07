"""
The control-plane API's own permission model — "who can manage the
manager" — dogfooded on `py-authz` itself rather than a bespoke RBAC
engine (see the control-panel architecture doc, §2.5).

Two resource types, each with the same `owner` -> `admin` -> `operator`
-> `auditor` -> `viewer` union chain (each relation implies every one
after it in the list, via `union`):

    `system` — global scope: managing service accounts and other
    operators' roles, and anything not scoped to one tenant. There is
    exactly one `system` object in practice (`SYSTEM_OBJECT_ID`,
    conventionally `system:default`) — this isn't a per-resource type the
    way `tenant`/an adopter's own models are, just a namespace for "the
    whole deployment" permissions.

    `tenant` — per-tenant scope: that tenant's models/migrations/grants.
    `tenant#auditor` gets read-only access to that tenant's audit log and
    relationship explorer. One `tenant:<id>` object per control-plane-
    managed tenant, `<id>` matching the `tenant_id` used everywhere else
    in this library (`TenantManager`, `MultiTenantAuthz`) — not OpenFGA's
    own `store_id`.

This model is synced to its OWN, dedicated OpenFGA store — never the
store any of `MultiTenantAuthz`'s actual tenants use, and never mixed
into an adopter's own tenant model. `System`/`Tenant` are deliberately
NOT registered into `py_authz.modeling.registry.registry` (the global
singleton `generate_model()` reads by default) for exactly that reason:
`generate_rbac_model()` below builds this model directly from an explicit
`models=` list (see `OpenFGAModelGenerator.generate()`), so nothing here
depends on, or leaks into, whatever an adopter's own process has
registered there.
"""

from typing import Any

from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.generator import generate_model


class System(ResourceModel):
    type = "system"

    owner = Relation("owner")
    admin = Relation("admin", union=["owner"])
    operator = Relation("operator", union=["admin"])
    auditor = Relation("auditor", union=["operator"])
    viewer = Relation("viewer", union=["auditor"])


class Tenant(ResourceModel):
    type = "tenant"

    owner = Relation("owner")
    admin = Relation("admin", union=["owner"])
    operator = Relation("operator", union=["admin"])
    auditor = Relation("auditor", union=["operator"])
    viewer = Relation("viewer", union=["auditor"])


#: Every relation implies the one before it in this order (`owner`
#: implies `admin`, which implies `operator`, ...) — `require_role()`
#: (see `auth.py`) uses this to accept "this role or anything above it"
#: without hand-listing every allowed relation at each call site.
ROLE_CHAIN: tuple[str, ...] = ("owner", "admin", "operator", "auditor", "viewer")

#: The explicit model set `generate_rbac_model()`/`ModelSync` build from
#: — deliberately NOT `registry.all()` (see module docstring).
RBAC_MODELS: tuple[type[ResourceModel], ...] = (System, Tenant)

#: Conventional single `system` object every control-plane deployment
#: checks against for global-scope actions (managing service accounts,
#: other operators' roles).
SYSTEM_OBJECT_ID = "default"


def generate_rbac_model() -> dict[str, Any]:
    """Build the OpenFGA schema for `RBAC_MODELS`, independent of the
    global `py_authz.modeling.registry.registry` singleton."""
    return generate_model(models=RBAC_MODELS)

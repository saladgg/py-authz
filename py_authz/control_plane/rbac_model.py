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

#: Subject types a role can be granted to (SEC3-3). Previously every
#: relation used `Relation`'s default `subjects=["user"]`, while
#: service-account principals were `service:<name>` — a type this model
#: never defined, so a real OpenFGA rejected every SA check and grant
#: with a 400 (only the type-permissive `InMemoryFGAClient` used by the
#: unit tests accepted it).
ROLE_SUBJECTS = ["user", "service_account"]

#: Prefix of every service-account principal id: `service_account:<sa_id>`
#: — keyed on the immutable account id, never its (reusable) name
#: (SEC3-2).
SERVICE_ACCOUNT_TYPE = "service_account"


class ServiceAccountSubject(ResourceModel):
    """Subject-only type: never the object of a check, only ever the
    `user` side of a role tuple."""

    type = SERVICE_ACCOUNT_TYPE


class System(ResourceModel):
    type = "system"

    owner = Relation("owner", subjects=ROLE_SUBJECTS)
    admin = Relation("admin", subjects=ROLE_SUBJECTS, union=["owner"])
    operator = Relation("operator", subjects=ROLE_SUBJECTS, union=["admin"])
    auditor = Relation("auditor", subjects=ROLE_SUBJECTS, union=["operator"])
    viewer = Relation("viewer", subjects=ROLE_SUBJECTS, union=["auditor"])


class Tenant(ResourceModel):
    type = "tenant"

    owner = Relation("owner", subjects=ROLE_SUBJECTS)
    admin = Relation("admin", subjects=ROLE_SUBJECTS, union=["owner"])
    operator = Relation("operator", subjects=ROLE_SUBJECTS, union=["admin"])
    auditor = Relation("auditor", subjects=ROLE_SUBJECTS, union=["operator"])
    viewer = Relation("viewer", subjects=ROLE_SUBJECTS, union=["auditor"])


#: Every relation implies the one before it in this order (`owner`
#: implies `admin`, which implies `operator`, ...) — `require_role()`
#: (see `auth.py`) uses this to accept "this role or anything above it"
#: without hand-listing every allowed relation at each call site.
ROLE_CHAIN: tuple[str, ...] = ("owner", "admin", "operator", "auditor", "viewer")

#: The explicit model set `generate_rbac_model()`/`ModelSync` build from
#: — deliberately NOT `registry.all()` (see module docstring).
RBAC_MODELS: tuple[type[ResourceModel], ...] = (ServiceAccountSubject, System, Tenant)

#: Conventional single `system` object every control-plane deployment
#: checks against for global-scope actions (managing service accounts,
#: other operators' roles).
SYSTEM_OBJECT_ID = "default"


def role_rank(role: str) -> int:
    """Position in `ROLE_CHAIN` — lower is more privileged (`owner` = 0)."""
    return ROLE_CHAIN.index(role)


def service_account_principal(account_id: str) -> str:
    return f"{SERVICE_ACCOUNT_TYPE}:{account_id}"


def generate_rbac_model() -> dict[str, Any]:
    """Build the OpenFGA schema for `RBAC_MODELS`, independent of the
    global `py_authz.modeling.registry.registry` singleton."""
    return generate_model(models=RBAC_MODELS)

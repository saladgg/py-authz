"""
Helpers for reasoning about a principal's RBAC role grants as a whole,
rather than one `can()` check at a time.

Used by the service-account routes (SEC3-2) to answer "does the caller
already hold every role this service account holds?" before letting them
rotate (and so obtain) its secret, and to clean up an SA's grants on
revoke; and by the operator role-assignment routes (SEC3-4) to compare
the caller's effective role against the role being granted.
"""

from dataclasses import dataclass

from py_authz.control_plane.rbac_model import (
    ROLE_CHAIN,
    SYSTEM_OBJECT_ID,
    System,
    Tenant,
    role_rank,
)
from py_authz.core.types import Identity, Resource

_SCOPED_TYPES = (System.type, Tenant.type)


@dataclass(frozen=True)
class RoleGrant:
    object: str  # "system:default" | "tenant:<id>"
    role: str

    @property
    def resource(self) -> Resource:
        type_, _, id_ = self.object.partition(":")
        return Resource(type=type_, id=id_)


async def direct_role_grants(rbac_authz, principal_id: str) -> list[RoleGrant]:
    """Every role tuple written directly for `principal_id` on a
    `system`/`tenant` object, across all pages. OpenFGA's Read needs at
    least an object *type* alongside a user filter, so this reads once per
    scoped type."""
    grants: list[RoleGrant] = []
    for type_ in _SCOPED_TYPES:
        token: str | None = None
        while True:
            page = await rbac_authz.read_tuples(
                user=principal_id, object=f"{type_}:", continuation_token=token
            )
            grants.extend(
                RoleGrant(object=t["object"], role=t["relation"])
                for t in page["tuples"]
                if t["relation"] in ROLE_CHAIN
            )
            token = page.get("continuation_token")
            if not token:
                break
    return grants


async def effective_role(rbac_authz, identity: Identity, resource: Resource) -> str | None:
    """The most privileged role `identity` holds on `resource` (directly
    or via union), or `None`."""
    for role in ROLE_CHAIN:
        if await rbac_authz.can(role, identity, resource):
            return role
    return None


async def is_system_owner(rbac_authz, identity: Identity) -> bool:
    return await rbac_authz.can("owner", identity, Resource(type=System.type, id=SYSTEM_OBJECT_ID))


async def dominates(rbac_authz, identity: Identity, grants: list[RoleGrant]) -> bool:
    """True if `identity` holds, on every object in `grants`, a role at
    least as privileged as the granted one — i.e. acting as the grantee
    could never give `identity` anything it doesn't already have.
    `system#owner` dominates everything."""
    if await is_system_owner(rbac_authz, identity):
        return True
    for grant in grants:
        held = await effective_role(rbac_authz, identity, grant.resource)
        if held is None or role_rank(held) > role_rank(grant.role):
            return False
    return True


async def delete_object_role_grants(
    rbac_authz, resource: Resource, *, reason: str, actor: Identity
) -> int:
    """Delete every role tuple on `resource` (e.g. `tenant:<id>`), for
    every subject. Used on tenant deprovision (SEC3-7) so a later tenant
    re-created under the same human-chosen id doesn't silently inherit
    the previous tenant's operators."""
    obj = resource.to_fga_object()
    grants: list[tuple[str, str]] = []
    token: str | None = None
    while True:
        page = await rbac_authz.read_tuples(object=obj, continuation_token=token)
        grants.extend(
            (t["user"], t["relation"]) for t in page["tuples"] if t["relation"] in ROLE_CHAIN
        )
        token = page.get("continuation_token")
        if not token:
            break

    for user, role in grants:
        await rbac_authz.revoke(Identity(id=user), role, resource, reason=reason, actor=actor)
    return len(grants)

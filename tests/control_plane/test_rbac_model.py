"""
Tests for py_authz.control_plane.rbac_model.

Uses `testkit.InMemoryFGAClient` (bound to a private registry containing
just `System`/`Tenant`) to confirm the `owner -> admin -> operator ->
auditor -> viewer` union chain actually grants what it's supposed to —
not just that `generate_rbac_model()` produces well-shaped JSON.
"""

import pytest

from py_authz.api import Authz
from py_authz.control_plane.rbac_model import (
    RBAC_MODELS,
    ROLE_CHAIN,
    SYSTEM_OBJECT_ID,
    System,
    Tenant,
    generate_rbac_model,
)
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.modeling.registry import registry as global_registry
from py_authz.testkit import InMemoryFGAClient


@pytest.fixture
def rbac_authz():
    reg = ResourceModelRegistry()
    reg.register(System)
    reg.register(Tenant)
    client = InMemoryFGAClient(model_registry=reg)
    return Authz(AuthzEngine(fga_client=client))


def test_rbac_models_are_not_registered_in_the_global_registry():
    """`System`/`Tenant` must never be registered into
    `py_authz.modeling.registry.registry` — that's where an *adopter's*
    own tenant models live, and mixing the two would leak RBAC types into
    every tenant's synced schema (see `rbac_model`'s module docstring)."""
    assert System not in global_registry.all()
    assert Tenant not in global_registry.all()


def test_generate_rbac_model_only_declares_system_and_tenant():
    model = generate_rbac_model()

    types = {t["type"] for t in model["type_definitions"]}
    assert types == {"user", "system", "tenant"}


def test_rbac_models_tuple_matches_the_two_classes():
    assert set(RBAC_MODELS) == {System, Tenant}


#: `Authz.can()` with a string action (rather than a bound `Relation`)
#: takes it at its `Resource`-or-`ResourceModel` argument literally — it
#: only converts `ResourceModel` -> `Resource` when `action` is a
#: `Relation` (see `Authz.can()`'s own docstring). `require_system_role`/
#: `require_tenant_role` (auth.py) always build a plain `Resource`
#: themselves before calling `can()`, so these tests do the same.
SYSTEM_RESOURCE = System(id=SYSTEM_OBJECT_ID).to_resource()


@pytest.mark.asyncio
async def test_owner_implies_every_lower_role(rbac_authz):
    alice = Identity(id="user:alice")
    await rbac_authz.grant(alice, "owner", System(id=SYSTEM_OBJECT_ID))

    for role in ROLE_CHAIN:
        assert await rbac_authz.can(role, alice, SYSTEM_RESOURCE) is True


@pytest.mark.asyncio
async def test_viewer_does_not_imply_owner(rbac_authz):
    bob = Identity(id="user:bob")
    await rbac_authz.grant(bob, "viewer", System(id=SYSTEM_OBJECT_ID))

    assert await rbac_authz.can("viewer", bob, SYSTEM_RESOURCE) is True
    assert await rbac_authz.can("owner", bob, SYSTEM_RESOURCE) is False
    assert await rbac_authz.can("admin", bob, SYSTEM_RESOURCE) is False


@pytest.mark.asyncio
async def test_operator_implies_auditor_and_viewer_but_not_admin(rbac_authz):
    carol = Identity(id="user:carol")
    await rbac_authz.grant(carol, "operator", System(id=SYSTEM_OBJECT_ID))

    assert await rbac_authz.can("operator", carol, SYSTEM_RESOURCE) is True
    assert await rbac_authz.can("auditor", carol, SYSTEM_RESOURCE) is True
    assert await rbac_authz.can("viewer", carol, SYSTEM_RESOURCE) is True
    assert await rbac_authz.can("admin", carol, SYSTEM_RESOURCE) is False
    assert await rbac_authz.can("owner", carol, SYSTEM_RESOURCE) is False


@pytest.mark.asyncio
async def test_system_and_tenant_roles_are_independent(rbac_authz):
    """A system role doesn't automatically grant the equivalent tenant
    role, or vice versa — see `auth.require_tenant_role`'s docstring on
    why the two scopes are deliberately independent."""
    dave = Identity(id="user:dave")
    await rbac_authz.grant(dave, "owner", System(id=SYSTEM_OBJECT_ID))

    assert await rbac_authz.can("owner", dave, SYSTEM_RESOURCE) is True
    assert await rbac_authz.can("viewer", dave, Tenant(id="acme").to_resource()) is False

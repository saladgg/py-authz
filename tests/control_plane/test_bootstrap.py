"""Tests for py_authz.control_plane.bootstrap.BreakGlassBootstrapper (CP-2)."""

import asyncio

import pytest

from py_authz.api import Authz
from py_authz.control_plane.bootstrap import BreakGlassBootstrapper
from py_authz.control_plane.rbac_model import RBAC_MODELS, SYSTEM_OBJECT_ID, System
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import Identity, Resource
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient


def _rbac_authz():
    reg = ResourceModelRegistry()
    # Strict mode + the full RBAC model (incl. the `service_account`
    # subject type): reject what a real OpenFGA rejects (ARCH3-9).
    for model in RBAC_MODELS:
        reg.register(model)
    client = InMemoryFGAClient(model_registry=reg, strict=True)
    return Authz(AuthzEngine(fga_client=client)), client


@pytest.mark.asyncio
async def test_bootstraps_the_configured_subject_when_store_is_empty():
    rbac_authz, client = _rbac_authz()
    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject="alice"
    )

    await bootstrapper.maybe_bootstrap(Identity(id="user:alice"))

    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    assert await rbac_authz.can("owner", Identity(id="user:alice"), system_resource) is True


@pytest.mark.asyncio
async def test_ignores_a_non_matching_subject():
    rbac_authz, client = _rbac_authz()
    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject="alice"
    )

    await bootstrapper.maybe_bootstrap(Identity(id="user:mallory"))

    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    assert await rbac_authz.can("owner", Identity(id="user:mallory"), system_resource) is False


@pytest.mark.asyncio
async def test_disabled_when_no_break_glass_subject_configured():
    rbac_authz, client = _rbac_authz()
    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject=None
    )

    await bootstrapper.maybe_bootstrap(Identity(id="user:alice"))

    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    assert await rbac_authz.can("owner", Identity(id="user:alice"), system_resource) is False


@pytest.mark.asyncio
async def test_never_fires_once_the_store_already_has_a_grant():
    """The instant `system:default` has ANY grant — break-glass or
    otherwise — this becomes a permanent no-op, even for the configured
    subject."""
    rbac_authz, client = _rbac_authz()
    # Someone else already got a legitimate grant, e.g. via a different
    # bootstrap mechanism.
    await rbac_authz.grant(Identity(id="user:legit-owner"), "owner", System(id=SYSTEM_OBJECT_ID))

    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject="alice"
    )
    await bootstrapper.maybe_bootstrap(Identity(id="user:alice"))

    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    assert await rbac_authz.can("owner", Identity(id="user:alice"), system_resource) is False


@pytest.mark.asyncio
async def test_is_idempotent_across_repeated_calls():
    rbac_authz, client = _rbac_authz()
    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject="alice"
    )

    await bootstrapper.maybe_bootstrap(Identity(id="user:alice"))
    await bootstrapper.maybe_bootstrap(Identity(id="user:alice"))  # must not raise / double-grant

    assert bootstrapper._known_non_empty is True


@pytest.mark.asyncio
async def test_double_checked_lock_catches_a_concurrent_bootstrap():
    """Two concurrent calls can both pass the outer `_known_non_empty`
    check before either acquires the lock — the re-check just inside it
    is what actually prevents a double grant, not the outer one alone.
    Simulated by holding the lock ourselves, starting a call (which then
    blocks on it), flipping `_known_non_empty` as if another call just
    finished, and releasing — the blocked call must see the fresh state
    and return without granting anything."""
    rbac_authz, client = _rbac_authz()
    bootstrapper = BreakGlassBootstrapper(
        rbac_authz=rbac_authz, rbac_fga_client=client, break_glass_subject="alice"
    )

    await bootstrapper._lock.acquire()
    task = asyncio.create_task(bootstrapper.maybe_bootstrap(Identity(id="user:alice")))
    await asyncio.sleep(0)  # let the task run up to (and block on) the lock

    bootstrapper._known_non_empty = True  # as if a concurrent call just finished
    bootstrapper._lock.release()
    await task

    system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    assert await rbac_authz.can("owner", Identity(id="user:alice"), system_resource) is False

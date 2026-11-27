"""Tests for py_authz.control_plane.role_grants — paging through the RBAC
store's tuples. Real OpenFGA returns `Read` results in pages with a
`continuation_token`; `InMemoryFGAClient` returns everything at once, so
these wrap it to serve one tuple per page and check nothing past the
first page is dropped."""

import pytest

from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System, Tenant
from py_authz.control_plane.role_grants import (
    RoleGrant,
    delete_object_role_grants,
    direct_role_grants,
)
from py_authz.core.types import Identity


class OneTuplePerPage:
    """Delegates to a real `Authz`, but pages `read_tuples` one tuple at
    a time (token = index of the next tuple), like a tiny OpenFGA page
    size would."""

    def __init__(self, authz):
        self._authz = authz
        self.reads: list[tuple[str | None, str | None]] = []

    def __getattr__(self, name):
        return getattr(self._authz, name)

    async def read_tuples(self, *, continuation_token=None, **filters):
        self.reads.append((filters.get("object"), continuation_token))
        everything = (await self._authz.read_tuples(**filters))["tuples"]
        start = int(continuation_token or 0)
        page = {"tuples": everything[start : start + 1]}
        if start + 1 < len(everything):
            page["continuation_token"] = str(start + 1)
        return page


ALICE = Identity(id="user:alice")
ROOT = Identity(id="user:root")


@pytest.fixture
def paging(rbac_authz):
    return OneTuplePerPage(rbac_authz)


@pytest.mark.asyncio
async def test_direct_role_grants_follows_continuation_tokens(rbac_authz, paging):
    await rbac_authz.grant(ALICE, "auditor", System(id=SYSTEM_OBJECT_ID))
    await rbac_authz.grant(ALICE, "admin", Tenant(id="acme"))
    await rbac_authz.grant(ALICE, "viewer", Tenant(id="globex"))

    grants = await direct_role_grants(paging, ALICE.id)

    assert sorted(grants, key=lambda g: g.object) == [
        RoleGrant(object="system:default", role="auditor"),
        RoleGrant(object="tenant:acme", role="admin"),
        RoleGrant(object="tenant:globex", role="viewer"),
    ]
    # One read for `system:`, then a second page was requested for `tenant:`.
    assert ("tenant:", "1") in paging.reads


@pytest.mark.asyncio
async def test_delete_object_role_grants_removes_grants_from_every_page(rbac_authz, paging):
    acme = Tenant(id="acme")
    subjects = [Identity(id=f"user:{name}") for name in ("alice", "bob", "carol")]
    for subject, role in zip(subjects, ("owner", "admin", "viewer"), strict=True):
        await rbac_authz.grant(subject, role, acme)
    await rbac_authz.grant(ALICE, "admin", Tenant(id="globex"))  # untouched

    deleted = await delete_object_role_grants(
        paging, acme.to_resource(), reason="deprovision", actor=ROOT
    )

    assert deleted == 3
    assert [token for obj, token in paging.reads if obj == "tenant:acme"] == [None, "1", "2"]
    assert (await rbac_authz.read_tuples(object="tenant:acme"))["tuples"] == []
    assert await rbac_authz.can("admin", ALICE, Tenant(id="globex").to_resource())

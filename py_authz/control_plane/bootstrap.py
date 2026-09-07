"""
Break-glass bootstrap for the very first `system#owner` (CP-2).

The dogfooded RBAC store (`rbac_model.py`) can only grant a role through
someone who already holds `system#owner` — but the very first operator
can't be granted a role by an operator who doesn't exist yet. This module
is the one, narrow, explicitly-documented escape hatch: an environment
variable (`ControlPlaneSettings.break_glass_subject`) names the subject
that should become `system#owner`, consumed *only* while the RBAC store
has zero tuples on `system:default` — the instant that stops being true
(the first grant lands, break-glass or otherwise), this becomes a
permanent no-op for the rest of the process's life, and every subsequent
run keeps checking the same "is it still empty" condition rather than a
one-shot flag, so restoring `system:default` to empty by hand (e.g. after
a mistaken revoke locked everyone out) re-opens the exact same door
instead of requiring a code change.

This is a deliberate, narrow escape hatch, not a general auth bypass:
it only ever grants the one specific, configured subject, only ever the
one specific `system#owner` relation, and only for as long as the store
has never had any grant at all.
"""

import asyncio

from py_authz.control_plane.rbac_model import SYSTEM_OBJECT_ID, System
from py_authz.core.types import Identity


class BreakGlassBootstrapper:
    def __init__(self, *, rbac_authz, rbac_fga_client, break_glass_subject: str | None):
        """
        Args:
            rbac_authz: `Authz` bound to the RBAC store — used to
                perform the actual grant (so it's audit-logged and
                cache-invalidated identically to any other grant).
            rbac_fga_client: The same store's raw `OpenFGAClient` (or
                `testkit.InMemoryFGAClient`) — used only to read whether
                `system:default` has any tuple yet, via `read_tuples()`.
            break_glass_subject: The bare subject (not `"user:<sub>"` —
                just the OIDC `sub`) to grant `system#owner` to. `None`
                disables break-glass entirely.
        """
        self._rbac_authz = rbac_authz
        self._rbac_fga_client = rbac_fga_client
        self._break_glass_subject = break_glass_subject
        self._lock = asyncio.Lock()
        #: Cheap short-circuit once we've observed the store is
        #: non-empty — avoids a `read_tuples()` round trip on every
        #: authenticated request for the rest of this process's life.
        self._known_non_empty = False

    async def maybe_bootstrap(self, identity: Identity) -> None:
        """
        Grant `identity` `system#owner` if it matches the configured
        break-glass subject AND `system:default` currently has zero
        tuples. Otherwise a no-op. Safe to call on every authenticated
        request — cheap once the store is non-empty (the common case
        almost immediately after first setup).
        """
        if self._known_non_empty or not self._break_glass_subject:
            return
        if identity.id != f"user:{self._break_glass_subject}":
            return

        async with self._lock:
            if self._known_non_empty:
                return

            existing = await self._rbac_fga_client.read_tuples(
                object=f"{System.type}:{SYSTEM_OBJECT_ID}"
            )
            if existing["tuples"]:
                self._known_non_empty = True
                return

            await self._rbac_authz.grant(
                identity,
                "owner",
                System(id=SYSTEM_OBJECT_ID),
                reason="break-glass bootstrap: first system#owner",
            )
            self._known_non_empty = True

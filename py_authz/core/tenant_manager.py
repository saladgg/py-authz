import json
import re
from contextlib import asynccontextmanager

from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.exceptions import InvalidAuthzRequest
from py_authz.core.logging import logger
from py_authz.core.model_sync import ModelSync
from py_authz.core.tenant_store import TenantStore

#: Conservative default allowlist for a `tenant_id` reaching `provision()`
#: — 1-128 chars, alphanumeric plus `_.-`, not starting/ending on a
#: separator. `tenant_id` can originate from request-derived input (e.g.
#: an `X-Tenant-ID` header via `MultiTenantAuthz`), so it's validated
#: before being used to name a real OpenFGA store or logged (see SEC2-3).
#: Override via `TenantManager(tenant_id_pattern=...)` if your tenant IDs
#: need a different shape (e.g. UUIDs, or a `:`-bearing convention).
DEFAULT_TENANT_ID_PATTERN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,126}[A-Za-z0-9])?$")


class TenantManager:
    """
    Handles tenant provisioning lifecycle.

    Responsibilities:
        - create store
        - sync model
        - persist mapping
    """

    def __init__(
        self,
        *,
        api_url: str,
        tenant_store: TenantStore,
        lock_manager=None,
        tenant_id_pattern: "re.Pattern[str] | str | None" = None,
    ):
        """
        Args:
            tenant_id_pattern: overrides `DEFAULT_TENANT_ID_PATTERN` — a
                compiled `re.Pattern` or a pattern string, matched with
                `fullmatch()` against every `tenant_id` passed to
                `provision()`. See SEC2-3: without this, an
                attacker-controlled `tenant_id` (e.g. reaching
                `MultiTenantAuthz` via an unauthenticated header) could
                force unbounded, arbitrarily-named OpenFGA store creation.
        """
        self.api_url = api_url
        self.tenant_store = tenant_store
        self.lock_manager = lock_manager
        self._tenant_id_pattern = (
            re.compile(tenant_id_pattern)
            if isinstance(tenant_id_pattern, str)
            else (tenant_id_pattern or DEFAULT_TENANT_ID_PATTERN)
        )

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    async def provision(self, tenant_id: str) -> str:
        """
        Provision a tenant.

        Returns:
            str: store_id

        Raises:
            InvalidAuthzRequest: if `tenant_id` doesn't match
                `tenant_id_pattern` — rejected before any lookup, lock
                acquisition, or store creation is attempted.
        """
        if not self._tenant_id_pattern.fullmatch(tenant_id):
            raise InvalidAuthzRequest(
                f"Invalid tenant_id {tenant_id!r}: must match {self._tenant_id_pattern.pattern!r}"
            )

        logger.info(json.dumps({"event": "provision_start", "tenant": tenant_id}))
        existing = await self.tenant_store.get(tenant_id)
        if existing:
            return existing

        async with self._provision_lock(tenant_id):
            # Re-check under lock: another caller may have provisioned
            # between our initial get() and lock acquisition.
            existing = await self.tenant_store.get(tenant_id)
            if existing:
                return existing

            client = OpenFGAClient.for_tenant(api_url=self.api_url)
            # Assigned only once `create_store()` succeeds. Referencing an
            # unassigned `store_id` in the log line below used to raise
            # `UnboundLocalError` when `create_store()` itself failed,
            # masking the real (and far more actionable) exception.
            store_id: str | None = None
            try:
                store_id = await client.create_store(name=tenant_id)
                client.store_id = store_id

                syncer = ModelSync(client)
                await syncer.sync(force=True)

                await self.tenant_store.set(tenant_id, store_id)

                logger.info(
                    json.dumps(
                        {
                            "event": "provision_success",
                            "tenant": tenant_id,
                            "store_id": store_id,
                        }
                    )
                )
                return store_id
            except Exception:
                logger.exception(
                    json.dumps(
                        {
                            "event": "provision_failed",
                            "tenant": tenant_id,
                            "store_id": store_id,
                        }
                    )
                )
                if store_id is not None:
                    # `create_store()` succeeded but a later step (model
                    # sync, persisting the mapping) failed — clean up the
                    # orphaned store instead of leaving it behind forever
                    # (see ARCH2-8). Best-effort: a failure here must not
                    # mask the original exception.
                    try:
                        await client.delete_store(store_id)
                    except Exception:
                        logger.exception(
                            json.dumps(
                                {
                                    "event": "provision_cleanup_failed",
                                    "tenant": tenant_id,
                                    "store_id": store_id,
                                }
                            )
                        )
                raise
            finally:
                await client.aclose()

    async def deprovision(self, tenant_id: str, *, model_registry=None) -> None:
        """
        Deprovision a tenant: delete its real OpenFGA store, then remove
        its `tenant_store` mapping (and, if `model_registry` is given,
        its `tenant_models`-shaped row too).

        Symmetric with `provision()`'s safety posture: `tenant_id` is
        validated against the same pattern first (rejected before any
        lookup or deletion is attempted), and start/success/failure are
        logged the same way. Deprovisioning a `tenant_id` with no known
        mapping is a no-op, not an error — matches `TenantStore.delete()`'s
        idempotent contract.

        The OpenFGA store is deleted *before* the tenant_store mapping is
        removed: if store deletion fails, the tenant is left exactly as
        provisioned (still resolvable, safe to retry) rather than in a
        state where the mapping is gone but the real store — and
        everything a caller might still expect to reach through it — is
        not. This is not locked the way `provision()` is (no concurrent
        "first deprovisioner wins" race to protect against beyond
        `delete_store()`/`delete()`'s own idempotency): deprovisioning is
        an explicit, operator-driven action, not something two concurrent
        first-callers might both trigger for the same tenant the way
        auto-provisioning can.

        Args:
            tenant_id: The tenant to deprovision.
            model_registry: Optional `ModelRegistry`-shaped object (see
                `core/model_registry.py`) whose row for `tenant_id`
                should also be removed. Defaults to `None` for backward
                compatibility with existing `TenantManager` construction,
                which doesn't take one — an orphaned `tenant_models` row
                left behind without it is harmless (nothing reads it once
                `tenant_store` no longer resolves that `tenant_id`), just
                not cleaned up.

        Raises:
            InvalidAuthzRequest: if `tenant_id` doesn't match
                `tenant_id_pattern`.
        """
        if not self._tenant_id_pattern.fullmatch(tenant_id):
            raise InvalidAuthzRequest(
                f"Invalid tenant_id {tenant_id!r}: must match {self._tenant_id_pattern.pattern!r}"
            )

        logger.info(json.dumps({"event": "deprovision_start", "tenant": tenant_id}))

        store_id = await self.tenant_store.get(tenant_id)
        if not store_id:
            logger.info(
                json.dumps(
                    {"event": "deprovision_noop", "tenant": tenant_id, "reason": "not_provisioned"}
                )
            )
            return

        client = OpenFGAClient.for_tenant(api_url=self.api_url, store_id=store_id)
        try:
            try:
                await client.delete_store(store_id)
            except Exception:
                logger.exception(
                    json.dumps(
                        {"event": "deprovision_failed", "tenant": tenant_id, "store_id": store_id}
                    )
                )
                raise

            await self.tenant_store.delete(tenant_id)
            if model_registry is not None:
                await model_registry.delete(tenant_id)

            logger.info(
                json.dumps(
                    {"event": "deprovision_success", "tenant": tenant_id, "store_id": store_id}
                )
            )
        finally:
            await client.aclose()

    @asynccontextmanager
    async def _provision_lock(self, tenant_id: str):
        if self.lock_manager is None:
            yield
            return

        async with self.lock_manager.lock(f"py_authz:provision:{tenant_id}"):
            yield

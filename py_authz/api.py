from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import TenantNotFoundError
from py_authz.core.model_sync import ModelSync
from py_authz.core.types import AuthzRequest, ContextualTuple, Identity, Resource
from py_authz.modeling.base import Relation, ResourceModel


def _to_resource(resource: "Resource | ResourceModel") -> Resource:
    """
    Normalize either a `Resource` or a `ResourceModel` instance to a
    `Resource` — the README and examples show passing a `ResourceModel`
    directly to `grant`/`revoke`/`grant_many`/`revoke_many` (e.g.
    `Document(id="report")`), same as `Authz.can()`/`enforce()` already
    accept.
    """
    if isinstance(resource, ResourceModel):
        return resource.to_resource()
    return resource


def _to_fga_object(resource: "Resource | ResourceModel") -> str:
    """
    Return the OpenFGA object string for either a `Resource` or a
    `ResourceModel` instance.

    `ResourceModel` doesn't itself have `to_fga_object()` (only `Resource`
    does), so calling it unconditionally raises `AttributeError` for the
    documented `ResourceModel` usage.
    """
    return _to_resource(resource).to_fga_object()


class Authz:
    """
    High-level authorization interface.

    This is the primary entry point for developers using py-authz.
    It provides a simple and expressive API for enforcing permissions.

    Example:
        authz = Authz(engine)

        allowed = await authz.enforce(
            action="view",
            user=Identity(id="user:123"),
            resource=Resource(type="document", id="456"),
        )
    """

    def __init__(self, engine: AuthzEngine):
        """
        Initialize the Authz interface.

        Args:
            engine (AuthzEngine):
                Core authorization engine instance.
        """
        self._engine = engine

    async def enforce(
        self,
        action: str,
        user: Identity,
        resource: Resource,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
        raise_on_denied: bool | None = None,
    ) -> bool:
        """
        Enforce an authorization decision.

        Args:
            action (str):
                Action to check (e.g., "viewer", "editor").

            user (Identity):
                The subject performing the action.

            resource (Resource):
                The target resource.

            context (Optional[dict]):
                ABAC context forwarded to OpenFGA conditions (e.g., current
                time, IP, request metadata).

            contextual_tuples (Optional[list[ContextualTuple]]):
                Per-request relationship tuples that participate in this
                check but are not persisted.

            raise_on_denied (Optional[bool]):
                Per-call override of the engine's configured default (see
                `AuthzEngine.enforce`). `Authz.require()` uses this
                instead of mutating the (possibly shared, concurrently
                used) engine's own `raise_on_denied` attribute.

        Returns:
            bool:
                True if access is allowed, False otherwise.

        Raises:
            AuthzError:
                If an error occurs during authorization.
        """
        request = AuthzRequest(
            identity=user,
            action=action,
            resource=resource,
            context=context,
            contextual_tuples=tuple(contextual_tuples) if contextual_tuples else None,
        )
        return await self._engine.enforce(request, raise_on_denied=raise_on_denied)

    async def can(
        self,
        action,
        user,
        resource,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ):
        """
        Supports both:
            - string actions ("viewer")
            - Relation objects (Document.view)

        Args:
            context (Optional[dict]):
                ABAC context forwarded to OpenFGA conditions.

            contextual_tuples (Optional[list[ContextualTuple]]):
                Per-request tuples that participate in this check but are
                not persisted.
        """

        # -------------------------------------------------
        # Relation-based API
        # -------------------------------------------------
        if isinstance(action, Relation):
            relation = action.name

            if isinstance(resource, ResourceModel):
                resource_obj = resource.to_resource()
            else:
                raise TypeError("Resource must be a ResourceModel instance")

        # -------------------------------------------------
        # String-based API (backward compatibility)
        # -------------------------------------------------
        else:
            relation = action
            resource_obj = resource

        return await self.enforce(
            action=relation,
            user=user,
            resource=resource_obj,
            context=context,
            contextual_tuples=contextual_tuples,
        )

    async def require(
        self,
        action: str,
        user: Identity,
        resource: Resource,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ) -> None:
        """
        Enforce permission and raise if denied.

        This is useful in cases where denial should interrupt execution.

        Example:
            await authz.require("edit", user, document)

        Args:
            context (Optional[dict]):
                ABAC context forwarded to OpenFGA conditions.

            contextual_tuples (Optional[list[ContextualTuple]]):
                Per-request tuples that participate in this check but are
                not persisted.

        Raises:
            AuthorizationDenied:
                If access is denied.
        """
        # `raise_on_denied=True` is passed per-call rather than mutating
        # `self._engine.raise_on_denied` — the engine is normally shared
        # across concurrent requests, and mutating shared state around an
        # `await` could let a concurrent `enforce()` call on another task
        # observe (or restore) the wrong value mid-flight. See SEC-6.
        await self.enforce(
            action,
            user,
            resource,
            context=context,
            contextual_tuples=contextual_tuples,
            raise_on_denied=True,
        )

    async def list_objects(
        self,
        relation,
        user: Identity,
        resource_type: str | None = None,
        *,
        context: dict | None = None,
        contextual_tuples: list[ContextualTuple] | None = None,
    ) -> list[str]:
        """
        Return all object IDs of a given type the user has `relation` on.

        Accepts either a string relation (in which case `resource_type` is
        required) or a `Relation` bound to a `ResourceModel` (type is derived).

        Returns:
            list[str]: object strings in "<type>:<id>" form, as returned by
            OpenFGA.

        Example:
            allowed_docs = await authz.list_objects(Document.viewer, alice)
            # ["document:roadmap", "document:design"]

            allowed_docs = await authz.list_objects("viewer", alice, "document")
        """
        if isinstance(relation, Relation):
            relation_name = relation.name
            if relation.resource_cls is None and resource_type is None:
                raise TypeError("Relation is unbound; pass resource_type explicitly.")
            type_name = resource_type or relation.resource_cls.type
        else:
            if not resource_type:
                raise TypeError("resource_type is required when relation is a string.")
            relation_name = relation
            type_name = resource_type

        return await self._engine.list_objects(
            user=user,
            relation=relation_name,
            resource_type=type_name,
            context=context,
            contextual_tuples=contextual_tuples,
        )

    async def sync_model(self) -> str:
        """
        Generate and sync model with OpenFGA.

        Returns:
            str: new model_id
        """
        if not self._engine.fga_client:
            raise RuntimeError("FGA client not configured")

        syncer = ModelSync(self._engine.fga_client)
        return await syncer.sync()

    async def grant(
        self,
        identity,
        relation: str,
        resource,
    ) -> None:
        """
        Grant a relation between a user and resource.

        Invalidates the cache entry for this exact (identity, relation,
        resource) triple, so an immediately-following `enforce`/`can` for
        the *same* relation doesn't return a stale cached "denied". This
        does NOT invalidate other relations implied by this one through
        the model (e.g. granting "owner" when "editor"/"viewer" union
        from it) — those remain cached until their TTL expires, since
        nothing here has static knowledge of the model's union graph. Use
        a short cache TTL, or `AuthzEngine.invalidate(...)` directly for
        relations you know are affected, if that matters for your use
        case.
        """
        await self._engine.fga_client.write_tuples(
            writes=[
                {
                    "user": identity.id,
                    "relation": relation,
                    "object": _to_fga_object(resource),
                }
            ]
        )
        await self._invalidate_cache(identity, relation, resource)

    async def revoke(
        self,
        identity,
        relation: str,
        resource,
    ) -> None:
        """
        Revoke a relation.

        See `grant`'s docstring — invalidates the cache entry for this
        exact (identity, relation, resource) triple only, not other
        relations implied by it through the model.
        """
        await self._engine.fga_client.write_tuples(
            writes=[],
            deletes=[
                {
                    "user": identity.id,
                    "relation": relation,
                    "object": _to_fga_object(resource),
                }
            ],
        )
        await self._invalidate_cache(identity, relation, resource)

    async def grant_many(
        self,
        tuples: list[tuple],
    ) -> None:
        """
        Grant many.
        tuples: [(identity, relation, resource)]

        See `grant`'s docstring — invalidates the cache entry for each
        exact (identity, relation, resource) triple granted.
        """
        writes = [
            {
                "user": i.id,
                "relation": r,
                "object": _to_fga_object(res),
            }
            for i, r, res in tuples
        ]

        await self._engine.fga_client.write_tuples(writes=writes)

        for identity, relation, resource in tuples:
            await self._invalidate_cache(identity, relation, resource)

    async def revoke_many(
        self,
        tuples: list[tuple],
    ) -> None:
        """
        Revoke many.
        tuples: [(identity, relation, resource)]

        See `grant`'s docstring — invalidates the cache entry for each
        exact (identity, relation, resource) triple revoked.
        """
        deletes = [
            {
                "user": i.id,
                "relation": r,
                "object": _to_fga_object(res),
            }
            for i, r, res in tuples
        ]

        await self._engine.fga_client.write_tuples(writes=[], deletes=deletes)

        for identity, relation, resource in tuples:
            await self._invalidate_cache(identity, relation, resource)

    async def _invalidate_cache(self, identity, relation: str, resource) -> None:
        if not self._engine.cache:
            return

        request = AuthzRequest(identity=identity, action=relation, resource=_to_resource(resource))
        await self._engine.cache.delete(request.cache_key())

    async def aclose(self) -> None:
        """
        Release the underlying `OpenFGAClient`'s HTTP connection pool.

        A standalone `Authz` constructed directly (not via
        `MultiTenantAuthz`) owns exactly one `OpenFGAClient` for its whole
        lifetime, so this is usually only worth calling on shutdown of a
        long-running process. `MultiTenantAuthz.aclose()` calls this on
        every cached tenant's `Authz` instance.
        """
        fga_client = self._engine.fga_client
        aclose = getattr(fga_client, "aclose", None)
        if aclose is not None:
            await aclose()


class MultiTenantAuthz:
    """
    Multi-tenant wrapper around Authz.

    `for_tenant()` caches one `Authz`/`AuthzEngine`/`OpenFGAClient` triple
    per tenant for the lifetime of this object — every distinct tenant a
    process ever resolves accumulates one open HTTP connection pool
    (`OpenFGAClient`'s `httpx.AsyncClient`) permanently. This cache has no
    eviction (no LRU, no TTL) by design: it's built for a small, bounded
    tenant count (the common case — a fixed set of orgs/customers a
    deployment serves), not an unbounded or highly dynamic one. If your
    tenant count is large or grows over the life of a long-running
    process, don't rely on this cache as-is — wrap `for_tenant()` with
    your own bounded cache (an LRU keyed on `tenant_id`, calling
    `authz.aclose()` on eviction), or resolve a fresh `Authz` per request
    without caching at all if your `tenant_resolver` is cheap enough.
    Call `aclose()` on process shutdown either way, to release whatever is
    currently cached.
    """

    def __init__(
        self,
        *,
        api_url: str,
        model_id: str | None,
        tenant_resolver,
        tenant_manager=None,
    ):
        self.api_url = api_url
        self.model_id = model_id
        self.tenant_resolver = tenant_resolver
        self.tenant_manager = tenant_manager

        self._cache = {}

    async def aclose(self) -> None:
        """
        Close every cached tenant's `Authz` (and its underlying
        `OpenFGAClient`), then clear the cache. Call this from your host
        app's shutdown hook (e.g. FastAPI's `lifespan`) — nothing else
        releases these connection pools.
        """
        for authz in self._cache.values():
            await authz.aclose()
        self._cache.clear()

    async def for_tenant(self, tenant_id: str):
        if tenant_id in self._cache:
            return self._cache[tenant_id]

        try:
            store_id = await self.tenant_resolver.resolve(tenant_id)
        except TenantNotFoundError:
            # This is the one, specific signal a `TenantResolver` is
            # expected to raise for "no such tenant yet" — see
            # `TenantNotFoundError`'s docstring. Any other exception
            # (a database timeout, a network error, a bug) is NOT caught
            # here: reinterpreting an arbitrary failure as "tenant not
            # found" could otherwise cause a transient resolver error for
            # an *existing* tenant to trigger provisioning a brand-new,
            # empty store and silently overwriting that tenant's mapping.
            if not self.tenant_manager:
                raise

            # Auto-provision tenant
            store_id = await self.tenant_manager.provision(tenant_id)

        client = OpenFGAClient(
            api_url=self.api_url,
            store_id=store_id,
            model_id=self.model_id,
        )

        engine = AuthzEngine(fga_client=client)

        from py_authz.api import Authz

        authz = Authz(engine)

        self._cache[tenant_id] = authz

        return authz

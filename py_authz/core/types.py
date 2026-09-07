from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class Identity:
    """
    Represents an authenticated subject (typically a user or service).

    This abstraction decouples your authorization system from any specific
    identity provider (e.g., Keycloak, Auth0).

    Attributes:
        id (str):
            Globally unique identifier of the identity.
            Example: "user:123", "service:billing-api"

        attributes (Optional[Dict[str, Any]]):
            Optional metadata associated with the identity.
            Can include roles, email, organization, etc.

    Notes:
        - The `id` should already be normalized to match your OpenFGA model.
        - This class is immutable (frozen=True) to prevent accidental mutation.
    """

    id: str
    attributes: dict[str, Any] | None = field(default=None)


@dataclass(frozen=True)
class Resource:
    """
    Represents a protected resource in the system.

    Attributes:
        type (str):
            Logical type/category of the resource.
            Example: "document", "project", "organization"

        id (str):
            Unique identifier of the resource.
            Example: "doc:456", "project:abc"

    Notes:
        - The combination of `type` and `id` is used to construct
          the OpenFGA object string: "{type}:{id}".
        - This class is immutable to ensure consistency during checks.
    """

    type: str
    id: str

    def to_fga_object(self) -> str:
        """
        Convert the resource into an OpenFGA-compatible object string.

        Returns:
            str: Object representation in the format "<type>:<id>"

        Example:
            Resource(type="document", id="456") -> "document:456"
        """
        return f"{self.type}:{self.id}"


@dataclass(frozen=True)
class ContextualTuple:
    """
    A relationship tuple supplied with a single request.

    Contextual tuples participate in OpenFGA evaluation alongside persisted
    tuples but are not stored. Useful for "what-if" checks, per-request
    grants, or modeling state that lives outside the FGA store.
    """

    user: str
    relation: str
    object: str

    def to_fga(self) -> dict[str, str]:
        return {"user": self.user, "relation": self.relation, "object": self.object}


@dataclass(frozen=True)
class AuthzRequest:
    """
    Encapsulates a single authorization check request.

    This object standardizes the input to the authorization engine,
    ensuring consistency and easier testing.

    Attributes:
        identity (Identity):
            The subject attempting the action.

        action (str):
            The action or relation being checked.
            Example: "viewer", "editor", "owner"

        resource (Resource):
            The target resource on which the action is performed.

        context (Optional[Dict[str, Any]]):
            ABAC context forwarded to OpenFGA conditions. Example uses
            include time-bounded access, IP allowlists, feature flags.

        contextual_tuples (Optional[tuple[ContextualTuple, ...]]):
            Tuples that participate in this request's evaluation but are
            not persisted. Stored as a tuple so AuthzRequest stays hashable.

    Notes:
        - This structure aligns closely with OpenFGA's tuple model.
        - Requests that carry context or contextual_tuples bypass the cache,
          since their decisions depend on per-request state.
    """

    identity: Identity
    action: str
    resource: Resource
    context: dict[str, Any] | None = field(default=None)
    contextual_tuples: tuple[ContextualTuple, ...] | None = field(default=None)

    def cache_key(self) -> str:
        """
        Generate a deterministic, collision-free cache key for this
        request.

        Each field is length-prefixed before joining. A naive
        `":".join(...)` (this method's previous implementation) is NOT
        injective: `Resource.id`'s own docstring recommends colon-bearing
        IDs like "doc:456", so e.g. `(user="user:123", action="viewer",
        resource=Resource("document", "doc:456"))` and `(user="user:123",
        action="viewer:document", resource=Resource("doc", "456"))` would
        collide onto the identical joined string — letting one request's
        cached decision silently authorize a completely unrelated one.
        Length-prefixing each field makes that collision impossible.

        Returns:
            str: Opaque cache key string. Do not attempt to parse it back
            apart or rely on its exact format — only on its uniqueness.
        """
        fields = (self.identity.id, self.action, self.resource.type, self.resource.id)
        return "|".join(f"{len(field)}:{field}" for field in fields)

    @staticmethod
    def identity_prefix(identity_id: str) -> str:
        """
        The leading fragment `cache_key()` always produces for a given
        `identity_id`, regardless of action/resource — i.e. every cache
        key for that identity starts with this string. Exposed as a
        public helper (rather than making callers reconstruct
        `cache_key()`'s length-prefixing scheme by hand) so a bulk
        "invalidate every cached decision for this user" operation — e.g.
        a cache backend's `delete_by_prefix()` (see `RedisCache`, CP-9) —
        can build the right prefix without depending on `cache_key()`'s
        internal format beyond "it starts with this".

        Does NOT include any `cache_namespace` an `AuthzEngine` may have
        applied on top (see `_scoped_cache_key`) — prepend that
        separately if the cache is namespaced (e.g. per-tenant).
        """
        return f"{len(identity_id)}:{identity_id}|"

    def is_cacheable(self) -> bool:
        """
        Per-request state (context, contextual tuples) makes results
        non-deterministic from the (user, relation, object) key alone, so
        such requests must skip the cache.
        """
        return not self.context and not self.contextual_tuples


@dataclass
class AuthzExplanation:
    """
    Result of an authorization explanation.
    """

    allowed: bool
    reason: str
    path: list[str] | None = None
    details: Any | None = None


@dataclass
class BulkAuthzResult:
    """
    One request's outcome from `AuthzEngine.bulk_enforce()`.

    `allowed` is `False` and `error` is set when this specific request's
    `enforce()` call raised (e.g. a transient `ExternalServiceError`) —
    check `error is not None` to distinguish "denied" from "failed to
    decide". See DX2-1: `bulk_enforce()` used to let such an exception
    propagate out of the whole batch (as an unhandled `ExceptionGroup`,
    not an `AuthzError`), discarding every already-completed result.
    """

    request: AuthzRequest
    allowed: bool
    error: Exception | None = None

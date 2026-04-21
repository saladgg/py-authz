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
            Optional contextual information for advanced authorization logic.
            Example: time-based access, IP address, feature flags, etc.

    Notes:
        - This structure aligns closely with OpenFGA's tuple model.
        - Context is reserved for future extensibility (e.g., ABAC).
    """

    identity: Identity
    action: str
    resource: Resource
    context: dict[str, Any] | None = field(default=None)

    def cache_key(self) -> str:
        """
        Generate a deterministic cache key for this request.

        Returns:
            str: Cache key string

        Example:
            "user:123:viewer:document:456"
        """
        return f"{self.identity.id}:{self.action}:{self.resource.type}:{self.resource.id}"


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
    request: AuthzRequest
    allowed: bool

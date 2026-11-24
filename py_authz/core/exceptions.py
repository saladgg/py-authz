class AuthzError(Exception):
    """
    Base exception for all py-authz errors.

    All custom exceptions in this library should inherit from this class.
    This allows users to catch all authz-related errors in a single block.

    Example:
        try:
            await authz.enforce(...)
        except AuthzError:
            handle_error()
    """

    def __init__(self, message: str, *, cause: Exception | None = None):
        """
        Initialize the base AuthzError.

        Args:
            message (str):
                Human-readable error message.

            cause (Optional[Exception]):
                Optional underlying exception that triggered this error.
                Useful for debugging and error chaining.
        """
        super().__init__(message)
        self.cause = cause


# ---------------------------------------------------------------------
# Authentication Errors
# ---------------------------------------------------------------------


class AuthenticationError(AuthzError):
    """
    Raised when authentication fails.

    Example cases:
        - Invalid or expired JWT
        - Missing required claims
        - Unknown signing key
    """

    pass


# ---------------------------------------------------------------------
# Authorization Errors
# ---------------------------------------------------------------------


class AuthorizationDenied(AuthzError):
    """
    Raised when an authorization check explicitly denies access.

    This is NOT a system failure — it is a valid outcome.

    Example:
        User tries to access a document they do not have permission for.
    """

    def __init__(self, message: str = "Access denied"):
        super().__init__(message)


class InvalidAuthzRequest(AuthzError):
    """
    Raised when an authorization request is malformed or invalid.

    Example cases:
        - Missing identity
        - Invalid resource format
        - Unsupported action
    """

    pass


class UpstreamRequestRejected(InvalidAuthzRequest):
    """
    Raised when OpenFGA rejects a request as invalid (HTTP 400/404/409/
    422) — an unknown type or relation, a malformed user, an invalid
    model, a store that doesn't exist.

    Before ARCH3-7 these surfaced as `ExternalServiceError`, i.e. "the
    service is unavailable" (a 503 from the control plane), so callers
    retried pointlessly, on-call saw false outages, and the FastAPI
    adapter's `fail_open=True` even *allowed* requests whose check was
    rejected because of a misconfiguration. This is a client/config
    error, not an availability one: it's an `InvalidAuthzRequest`, and is
    never retried or failed open.

    Attributes:
        status_code: the HTTP status OpenFGA returned.
        detail: OpenFGA's error message, when it sent one.
        service: always "openfga" today.
    """

    def __init__(
        self,
        message: str,
        *,
        status_code: int,
        detail: str | None = None,
        service: str = "openfga",
    ):
        super().__init__(message)
        self.status_code = status_code
        self.detail = detail
        self.service = service


# ---------------------------------------------------------------------
# External Service Errors
# ---------------------------------------------------------------------


class ExternalServiceError(AuthzError):
    """
    Raised when an external dependency fails.

    This includes:
        - OpenFGA API errors
        - Keycloak failures
        - Network issues

    These are typically retryable depending on context.
    """

    def __init__(
        self,
        message: str,
        *,
        service: str | None = None,
        cause: Exception | None = None,
    ):
        """
        Args:
            message (str):
                Description of the failure.

            service (Optional[str]):
                Name of the external service (e.g., "openfga", "keycloak").

            cause (Optional[Exception]):
                Original exception that caused the failure.
        """
        super().__init__(message, cause=cause)
        self.service = service


class ServiceUnavailable(ExternalServiceError):
    """
    Raised when an external service is unavailable.

    Example:
        - OpenFGA is down
        - Timeout when calling API
    """

    pass


class ServiceTimeout(ExternalServiceError):
    """
    Raised when a request to an external service times out.
    """

    pass


class LockAcquisitionTimeout(ExternalServiceError):
    """
    Raised when a distributed lock (`RedisLockManager`/`RedisLock`) could
    not be acquired before its timeout elapsed — e.g. Redis is
    unreachable, or the lock is held by another process for longer than
    expected. Inherits from `ExternalServiceError` (rather than being a
    bare `TimeoutError`) so it's caught by the same fail-open/fail-closed
    handling in the FastAPI adapter and the same CLI exit-code bucket as
    any other external-dependency failure (see ARCH2-4).
    """

    pass


class IdentityProviderUnavailable(ExternalServiceError):
    """
    Raised when the identity provider itself — not a specific token — is
    unreachable: an OIDC discovery-document or JWKS fetch failed due to a
    network error, timeout, or non-2xx response. Distinct from
    `AuthenticationError` (which means a specific token is invalid): this
    signals the IdP dependency is down, which callers may want to
    translate to a 503 rather than a 401 (see `KeycloakAuthMiddleware`
    and ARCH2-7).
    """

    pass


# ---------------------------------------------------------------------
# Configuration Errors
# ---------------------------------------------------------------------


class ConfigurationError(AuthzError):
    """
    Raised when the system is misconfigured.

    Example cases:
        - Missing OpenFGA credentials
        - Invalid configuration values
    """

    pass


class ModelValidationError(ConfigurationError):
    """
    Raised when an OpenFGA authorization model fails validation —
    malformed relation definitions, an unrecognized rewrite rule, or a
    circular relation dependency (see `DefaultModelValidator`/
    `detect_cycles`). This is a config-shaped mistake (an incorrectly
    declared model), not a runtime bug, so it inherits from
    `ConfigurationError` and shares its CLI exit code (see ARCH2-5).
    """

    pass


# ---------------------------------------------------------------------
# Multi-Tenancy Errors
# ---------------------------------------------------------------------


class TenantNotFoundError(AuthzError):
    """
    Raised by a `TenantResolver` to signal that a tenant has no store
    mapping yet — the one, specific condition under which
    `MultiTenantAuthz.for_tenant()` is allowed to fall back to
    auto-provisioning via a configured `TenantManager`.

    `TenantResolver` implementations MUST raise this (not a bare
    `ValueError`/`KeyError`/etc.) to signal "no such tenant yet". Any other
    exception — a database timeout, a network error, a bug — must be
    allowed to propagate as a hard failure instead of being silently
    reinterpreted as "this tenant doesn't exist", which could otherwise
    cause a transient resolver failure for an *existing* tenant to trigger
    provisioning a brand-new, empty store and overwriting that tenant's
    mapping.
    """

    pass

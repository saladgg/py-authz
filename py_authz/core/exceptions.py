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

class DRFAuthzError(Exception):
    """Base error for drf-authz."""


class ConfigurationError(DRFAuthzError):
    """Missing or invalid configuration."""


class AuthenticationError(DRFAuthzError):
    """Authentication-related error."""


class AuthorizationError(DRFAuthzError):
    """Authorization-related error."""
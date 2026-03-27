"""Custom exceptions for django-authz.

All library exceptions inherit from :class:`DjangoAuthzError` so callers can
catch the entire hierarchy with a single ``except DjangoAuthzError`` clause.

Hierarchy::

    DjangoAuthzError
    ├── ConfigurationError   — missing or invalid settings
    ├── AuthenticationError  — token decode / OIDC failures
    └── AuthorizationError   — FGA check failures
"""


class DjangoAuthzError(Exception):
    """Base error for django-authz."""


class ConfigurationError(DjangoAuthzError):
    """Missing or invalid configuration.

    Raised when required settings (e.g. ``JWKS_URL``, ``OPENFGA_API_URL``) are
    absent or logically inconsistent.
    """


class AuthenticationError(DjangoAuthzError):
    """Authentication-related error.

    Raised when a JWT cannot be decoded/verified, or when an OIDC flow fails.
    """


class AuthorizationError(DjangoAuthzError):
    """Authorization-related error.

    Raised when an OpenFGA check call itself fails (network error, bad
    response, etc.) — *not* when the check returns ``allowed=False``.
    """

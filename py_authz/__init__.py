"""
py-authz

A framework-agnostic authorization library built on OpenFGA and modern Python practices.

Public API:
    - Authz (main entry point), MultiTenantAuthz (one store per tenant)
    - SyncAuthz (blocking facade for WSGI/sync code — see py_authz.sync)
    - Identity, Resource, ContextualTuple (domain models)
    - the exception hierarchy, rooted at AuthzError
    - __version__
"""

from importlib.metadata import PackageNotFoundError, version

from py_authz.api import Authz, MultiTenantAuthz
from py_authz.core.exceptions import (
    AuthenticationError,
    AuthorizationDenied,
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    IdentityProviderUnavailable,
    InvalidAuthzRequest,
    LockAcquisitionTimeout,
    ModelValidationError,
    ServiceTimeout,
    ServiceUnavailable,
    TenantNotFoundError,
    UpstreamRequestRejected,
)
from py_authz.core.types import AuthzExplanation, ContextualTuple, Identity, Resource
from py_authz.sync import SyncAuthz

try:
    __version__ = version("py-authz")
except PackageNotFoundError:  # a source checkout that was never installed
    __version__ = "0.0.0+unknown"

__all__ = [
    "AuthenticationError",
    "AuthorizationDenied",
    "Authz",
    "AuthzError",
    "AuthzExplanation",
    "ConfigurationError",
    "ContextualTuple",
    "ExternalServiceError",
    "Identity",
    "IdentityProviderUnavailable",
    "InvalidAuthzRequest",
    "LockAcquisitionTimeout",
    "ModelValidationError",
    "MultiTenantAuthz",
    "Resource",
    "ServiceTimeout",
    "ServiceUnavailable",
    "SyncAuthz",
    "TenantNotFoundError",
    "UpstreamRequestRejected",
    "__version__",
]

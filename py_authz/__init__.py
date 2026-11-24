"""
py-authz

A framework-agnostic authorization library built on OpenFGA and modern Python practices.

Public API:
    - Authz (main entry point)
    - SyncAuthz (blocking facade for WSGI/sync code — see py_authz.sync)
    - Identity, Resource (domain models)
"""

from py_authz.api import Authz
from py_authz.core.types import ContextualTuple, Identity, Resource
from py_authz.sync import SyncAuthz

__all__ = [
    "Authz",
    "ContextualTuple",
    "Identity",
    "Resource",
    "SyncAuthz",
]

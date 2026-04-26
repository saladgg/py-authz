"""
py-authz

A framework-agnostic authorization library built on OpenFGA and modern Python practices.

Public API:
    - Authz (main entry point)
    - Identity, Resource (domain models)
"""

from py_authz.api import Authz
from py_authz.core.types import ContextualTuple, Identity, Resource

__all__ = [
    "Authz",
    "ContextualTuple",
    "Identity",
    "Resource",
]

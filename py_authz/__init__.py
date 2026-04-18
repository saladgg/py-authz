"""
py-authz

A framework-agnostic authorization library built on OpenFGA and modern Python practices.

Public API:
    - Authz (main entry point)
    - Identity, Resource (domain models)
"""

from py_authz.api import Authz
from py_authz.core.types import Identity, Resource

__all__ = [
    "Authz",
    "Identity",
    "Resource",
]

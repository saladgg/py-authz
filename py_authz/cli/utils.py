"""Backward-compatible alias: `load_module` moved to
`py_authz.utils.modules` (ARCH3-17) so the control plane no longer imports
the CLI package."""

from py_authz.utils.modules import load_module

__all__ = ["load_module"]

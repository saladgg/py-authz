"""ARCH3-17: the package root exports the public surface and a version."""

import py_authz


def test_root_exports_core_api_and_exceptions():
    for name in (
        "Authz",
        "MultiTenantAuthz",
        "SyncAuthz",
        "Identity",
        "Resource",
        "AuthzError",
        "AuthorizationDenied",
        "UpstreamRequestRejected",
        "ModelValidationError",
    ):
        assert name in py_authz.__all__
        assert getattr(py_authz, name) is not None


def test_version_matches_installed_metadata():
    from importlib.metadata import version

    assert py_authz.__version__ == version("py-authz")


def test_cli_utils_alias_still_works():
    from py_authz.cli.utils import load_module as legacy
    from py_authz.utils.modules import load_module

    assert legacy is load_module

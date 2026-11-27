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


def test_version_falls_back_when_package_metadata_is_missing(monkeypatch):
    """A source checkout that was never installed has no distribution
    metadata; importing the package must still work, with a placeholder
    version."""
    import importlib
    import importlib.metadata

    def not_installed(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", not_installed)
    try:
        reloaded = importlib.reload(py_authz)
        assert reloaded.__version__ == "0.0.0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(py_authz)

    assert py_authz.__version__ == importlib.metadata.version("py-authz")

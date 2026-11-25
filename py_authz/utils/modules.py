import importlib

from py_authz.core.exceptions import ConfigurationError


def load_module(module_path: str) -> None:
    """
    Dynamically import a module so that ResourceModels
    get registered via side-effects.

    Example:
        load_module("myapp.authz_models")
    """
    try:
        importlib.import_module(module_path)
    except ModuleNotFoundError as e:
        # `ConfigurationError` (an `AuthzError`), not a bare `RuntimeError`
        # — a bad `--module` path is a user mistake, not a library bug;
        # see ARCH2-5.
        raise ConfigurationError(f"Failed to import module '{module_path}': {e}") from e

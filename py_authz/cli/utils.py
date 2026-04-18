import importlib


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
        raise RuntimeError(f"Failed to import module '{module_path}': {e}") from e

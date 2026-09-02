import os

from py_authz.core.exceptions import ConfigurationError


def get_env(name: str, default=None, required: bool = False):
    value = os.getenv(name, default)

    if required and not value:
        # `ConfigurationError` (an `AuthzError`), not a bare `RuntimeError`
        # — a missing env var is the single most common real CLI
        # misconfiguration, and this is what lets the CLI's top-level
        # handler print a friendly message and exit code 2 instead of a
        # raw traceback (see ARCH2-5).
        raise ConfigurationError(f"Missing required environment variable: {name}")

    return value

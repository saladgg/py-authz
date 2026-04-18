import os


def get_env(name: str, default=None, required: bool = False):
    value = os.getenv(name, default)

    if required and not value:
        raise RuntimeError(f"Missing required environment variable: {name}")

    return value

from importlib.metadata import version

try:
    __version__ = version("drf-authz")
except Exception:  # pragma: no cover
    __version__ = "0.0.0"
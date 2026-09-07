def require_redis():
    """
    Ensure Redis dependency is available.

    Returns:
        redis.asyncio module

    Raises:
        RuntimeError: if redis is not installed
    """
    try:
        import redis.asyncio as redis

        return redis
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("Redis support requires `pip install py-authz[redis]`") from e


def require_postgres():
    """
    Ensure asyncpg dependency is available.
    """
    try:
        import asyncpg

        return asyncpg
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("PostgreSQL support requires `pip install py-authz[postgres]`") from e


def require_fast_api():
    """
    Ensure FastAPI dependency is available.
    """
    try:
        from fastapi import HTTPException, Request, status

        return Request, HTTPException, status
    except ImportError as e:  # pragma: no cover
        raise RuntimeError("FastAPI support requires `pip install py-authz[fastapi]`") from e


def require_argon2():
    """
    Ensure `argon2-cffi` is available.

    Used by the control-plane API's service-account credential hashing
    (`py_authz/control_plane/security.py`) — argon2, never a reversible
    encoding or a weaker hash, for the one endpoint in this library that
    authenticates a bearer secret directly rather than delegating to an
    IdP (see the control-panel architecture doc, §2.6).
    """
    try:
        from argon2 import PasswordHasher
        from argon2.exceptions import VerifyMismatchError

        return PasswordHasher, VerifyMismatchError
    except ImportError as e:  # pragma: no cover
        raise RuntimeError(
            "Service-account credentials require `pip install py-authz[control-plane]`"
        ) from e

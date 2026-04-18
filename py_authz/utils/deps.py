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

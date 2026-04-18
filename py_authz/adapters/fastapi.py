from collections.abc import Callable

from fastapi import HTTPException, Request, status

from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel

# -------------------------------------------------------------------
# Helper: Default extractors
# -------------------------------------------------------------------


def default_user_getter(request: Request) -> Identity:
    """
    Default way to extract user from FastAPI request.

    Assumes middleware has set:
        request.state.user = Identity(...)
    """
    user = getattr(request.state, "user", None)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized",
        )

    return user


# -------------------------------------------------------------------
# Dependency-based enforcement
# -------------------------------------------------------------------


def require_dependency(
    authz,
    relation: Relation,
    *,
    resource_getter: Callable[..., ResourceModel],
    user_getter: Callable[[Request], Identity] = default_user_getter,
):
    """
    FastAPI dependency for enforcing authorization.

    Example:
        @app.get("/docs/{doc_id}")
        async def handler(
            doc_id: str,
            _: None = Depends(
                require_dependency(
                    authz,
                    Document.view,
                    resource_getter=lambda request, doc_id: Document(doc_id),
                )
            )
        ):
            ...
    """

    async def dependency(request: Request, **kwargs):
        user = user_getter(request)
        resource = resource_getter(request, **kwargs)

        allowed = await authz.can(relation, user, resource)

        if not allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: cannot {relation.name}",
            )

    return dependency


# -------------------------------------------------------------------
# Decorator-based enforcement (FastAPI-friendly)
# -------------------------------------------------------------------


def require_fastapi(
    authz,
    relation: Relation,
    *,
    resource_getter: Callable[..., ResourceModel],
    user_getter: Callable[[Request], Identity] = default_user_getter,
):
    """
    Decorator for FastAPI route handlers.

    Example:
        @app.get("/docs/{doc_id}")
        @require_fastapi(
            authz,
            Document.view,
            resource_getter=lambda request, doc_id: Document(doc_id),
        )
        async def handler(request: Request, doc_id: str):
            ...
    """

    def decorator(func):
        import inspect
        from functools import wraps

        is_async = inspect.iscoroutinefunction(func)

        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Extract request from args/kwargs
            request: Request | None = kwargs.get("request")

            if request is None:
                # fallback: find Request in args
                for arg in args:
                    if isinstance(arg, Request):
                        request = arg
                        break

            if request is None:
                raise RuntimeError("FastAPI Request object not found")

            user = user_getter(request)
            # remove duplicate request
            filtered_kwargs = {k: v for k, v in kwargs.items() if k != "request"}
            resource = resource_getter(request, **filtered_kwargs)

            allowed = await authz.can(relation, user, resource)

            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Forbidden: cannot {relation.name}",
                )

            if is_async:
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


def tenant_from_request(request: Request) -> str:
    """
    Extract tenant from request.

    Customize this:
        - header (X-Tenant-ID)
        - subdomain
        - JWT claims
    """
    tenant = request.headers.get("X-Tenant-ID")

    if not tenant:
        raise HTTPException(status_code=400, detail="Missing tenant")

    return tenant

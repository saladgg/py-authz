import inspect
import uuid
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING

from py_authz.core.context import set_request_id
from py_authz.core.exceptions import ExternalServiceError
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.utils.deps import require_fast_api

if TYPE_CHECKING:
    from fastapi import HTTPException, Request, status
else:
    Request, HTTPException, status = require_fast_api()

# A getter may be a plain sync function or an `async def` — the latter is
# what makes an actual resource lookup practical (loading the record being
# authorized almost always needs an async DB call).
type MaybeAsync[T] = T | Awaitable[T]


async def _resolve[T](value: MaybeAsync[T]) -> T:
    """
    Await `value` if it's awaitable (i.e. it came from an `async def`
    getter); otherwise return it as-is. This is what lets
    `resource_getter`/`user_getter` be sync or async without callers
    having to declare which.
    """
    if inspect.isawaitable(value):
        return await value
    return value  # type: ignore[return-value]


async def _resolve_authz(authz, request: "Request"):
    """
    `authz` may be a static `Authz` instance, or a sync/async callable
    taking the current `Request` and returning one — the mechanism for
    per-request-resolved authorization. This is what lets a single set of
    routes serve every tenant in a multi-tenant app, each backed by its
    own store:

        mt = MultiTenantAuthz(...)

        async def authz_for_request(request: "Request") -> Authz:
            return await mt.for_tenant(tenant_from_request(request))

        require_fastapi(authz_for_request, Document.viewer, ...)

    A plain `Authz` instance is never itself callable (it defines no
    `__call__`), so `callable(authz)` unambiguously distinguishes the two
    without needing an `Authz` import here.
    """
    if callable(authz):
        return await _resolve(authz(request))
    return authz


async def _enforce(
    authz,
    request: "Request",
    relation: Relation,
    user: Identity,
    resource: ResourceModel,
    *,
    fail_open: bool,
) -> None:
    """
    Resolve `authz` (see `_resolve_authz`) and run the authorization
    check, raising the appropriate `HTTPException`.

    A dependency failure (`ExternalServiceError` — OpenFGA unreachable or
    timed out, a `LockAcquisitionTimeout` during per-request tenant
    provisioning, etc.) is translated to a 503 by default
    (`fail_open=False`): fail-closed, so an availability incident is
    never indistinguishable from an actual authorization decision (a 403
    "denied"). Pass `fail_open=True` to let the request through instead
    when the dependency is degraded — only appropriate for routes where
    staying available matters more than strict enforcement during an
    outage.

    `authz` resolution happens *inside* this try/except (not before it,
    as it previously did) — a `MultiTenantAuthz`-backed resolver can
    itself hit `ExternalServiceError` (e.g. tenant auto-provisioning
    timing out on a contended lock — see ARCH2-4), and that failure needs
    the same fail-open/fail-closed treatment as a failure in the check
    itself, not an unhandled 500.
    """
    try:
        resolved_authz = await _resolve_authz(authz, request)
        allowed = await resolved_authz.can(relation, user, resource)
    except ExternalServiceError as exc:
        if fail_open:
            return
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Authorization service unavailable",
        ) from exc

    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Forbidden: cannot {relation.name}",
        )


# -------------------------------------------------------------------
# Helper: Default extractors
# -------------------------------------------------------------------


def default_user_getter(request: "Request") -> Identity:
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
    resource_getter: Callable[..., MaybeAsync[ResourceModel]],
    user_getter: Callable[["Request"], MaybeAsync[Identity]] = default_user_getter,
    fail_open: bool = False,
):
    """
    FastAPI dependency for enforcing authorization.

    `authz` may be a static `Authz` instance, or a sync/async callable
    taking the `Request` and returning one — for per-request-resolved
    authorization (e.g. multi-tenant). See `_resolve_authz`'s docstring
    for a worked example.

    `resource_getter`/`user_getter` may be sync or `async def` — the
    common real case for a resource lookup is an async DB call (does this
    record exist, who owns it, what's its parent for a hierarchy check).

    `fail_open` controls what happens when the authorization backend
    itself fails (OpenFGA unreachable/timed out — `ExternalServiceError`).
    Default `False`: the request is rejected with a 503, kept distinct
    from a 403 "denied" decision. Pass `True` to let the request through
    instead for routes where availability matters more than strict
    enforcement during an outage.

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

    Async resource_getter example:
        async def load_document(request, doc_id: str) -> Document:
            record = await db.documents.get(doc_id)
            return Document(id=record.id)

        require_dependency(authz, Document.view, resource_getter=load_document)
    """

    async def dependency(request: "Request", **kwargs):
        user = await _resolve(user_getter(request))
        resource = await _resolve(resource_getter(request, **kwargs))

        await _enforce(authz, request, relation, user, resource, fail_open=fail_open)

    return dependency


# -------------------------------------------------------------------
# Decorator-based enforcement (FastAPI-friendly)
# -------------------------------------------------------------------


def require_fastapi(
    authz,
    relation: Relation,
    *,
    resource_getter: Callable[..., MaybeAsync[ResourceModel]],
    user_getter: Callable[["Request"], MaybeAsync[Identity]] = default_user_getter,
    fail_open: bool = False,
):
    """
    Decorator for FastAPI route handlers.

    `authz` may be a static `Authz` instance or a per-request resolver
    callable; `resource_getter`/`user_getter` may be sync or `async def`;
    `fail_open` controls the fail-open/fail-closed policy — see
    `require_dependency`'s docstring for all three.

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

            user = await _resolve(user_getter(request))
            # remove duplicate request
            filtered_kwargs = {k: v for k, v in kwargs.items() if k != "request"}
            resource = await _resolve(resource_getter(request, **filtered_kwargs))

            await _enforce(authz, request, relation, user, resource, fail_open=fail_open)

            if is_async:
                return await func(*args, **kwargs)
            else:
                return func(*args, **kwargs)

        return wrapper

    return decorator


def tenant_from_request(request: "Request") -> str:
    """
    Extract tenant from the `X-Tenant-ID` request header.

    **Insecure by itself — demo/development use only.** This header is
    entirely caller-controlled: nothing here verifies it against the
    authenticated identity, so ANY caller (authenticated or not) can
    select an arbitrary tenant's store just by setting this header — a
    direct cross-tenant authorization bypass if identities, object IDs,
    or grants happen to overlap across tenants (see SEC2-2). Do not use
    this in front of real authentication without first cross-checking its
    value against something verified.

    Prefer `tenant_from_verified_claim()` (reads a tenant claim from the
    validated JWT instead — see `OIDCJWTValidator.to_identity()`) or a
    subdomain resolved server-side.
    """
    tenant = request.headers.get("X-Tenant-ID")

    if not tenant:
        raise HTTPException(status_code=400, detail="Missing tenant")

    return tenant


def tenant_from_verified_claim(claim: str = "tenant_id") -> Callable[["Request"], str]:
    """
    Return a tenant-resolution callable that reads `claim` from the
    *authenticated identity's verified token claims*
    (`request.state.user.attributes`, populated by
    `OIDCJWTValidator.to_identity()`/`KeycloakAuthMiddleware`) — never
    from a raw, caller-controlled request header. This is the safe
    alternative to `tenant_from_request` for any deployment with real
    authentication: a value inside a signature-verified JWT can't be
    forged by the caller the way an arbitrary header can (see SEC2-2).

    Requires the configured IdP to actually issue a `claim` (e.g. a
    custom `tenant_id`/`org_id` claim) — raises a 400 if it's missing, or
    if the request has no authenticated identity at all.

    Example:
        async def authz_for_request(request: Request) -> Authz:
            tenant_id = tenant_from_verified_claim()(request)
            return await mt.for_tenant(tenant_id)

        require_fastapi(authz_for_request, Document.view, ...)
    """

    def _resolve(request: "Request") -> str:
        user = getattr(request.state, "user", None)
        tenant = user.attributes.get(claim) if user is not None and user.attributes else None

        if not tenant:
            raise HTTPException(
                status_code=400,
                detail=f"Missing '{claim}' claim on authenticated identity",
            )

        return tenant

    return _resolve


async def request_context_middleware(request: "Request", call_next):
    request_id = str(uuid.uuid4())

    set_request_id(request_id)

    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id

    return response

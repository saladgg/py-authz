"""
Operator authentication + dogfooded RBAC + service-account scope checks
(CP-2, CP-3).

Every non-`/health` route in this API depends on one of the dependency
factories below (`require_system_role`/`require_tenant_role`), which:

    1. resolve the caller's `CurrentPrincipal` — either an operator (an
       OIDC bearer token, verified via `OIDCJWTValidator`) or a service
       account (a `Bearer pasa_<id>.<secret>` token, verified against
       `service_accounts.secret_hash`) — see `get_current_principal()`;
    2. for a service account, check its coarse-grained scopes *first*
       (`scope=`, a required argument on every factory — see
       `scopes.py`; SEC3-1) — before anything per-tenant;
    3. run the actual `authz.can(...)` check against the RBAC store,
       exactly like any other `py-authz` consumer would.

Nothing here reimplements authorization — it's the same `Authz.can()`
surface as every other route in this API's underlying library.
"""

import asyncio
import hashlib
import ipaddress
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import anyio
from fastapi import Depends, HTTPException, Request

from py_authz.control_plane.rbac_model import (
    ROLE_CHAIN,
    SYSTEM_OBJECT_ID,
    System,
    Tenant,
    service_account_principal,
)
from py_authz.control_plane.scopes import ANY_PRINCIPAL, Scope
from py_authz.control_plane.security import (
    MalformedServiceAccountToken,
    parse_account_id,
    verify_secret,
)
from py_authz.core.exceptions import AuthenticationError, AuthorizationDenied, InvalidAuthzRequest
from py_authz.core.types import Identity, Resource

logger = logging.getLogger("py_authz.control_plane.auth")


@dataclass(frozen=True)
class CurrentPrincipal:
    """The authenticated caller of a control-plane API request — either
    kind of principal this API accepts."""

    identity: Identity
    kind: str  # "operator" | "service_account"
    scopes: tuple[str, ...] = ()
    #: For operators: the verified `sub`/`email` claims.
    claims: dict | None = None


def _bearer_token(request: Request) -> str:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise AuthenticationError("Missing or malformed Authorization header")
    return token


async def _authenticate_operator(request: Request, token: str) -> CurrentPrincipal:
    validator = request.app.state.oidc_validator
    payload = await validator.validate(token)
    identity = validator.to_identity(payload)

    # `record_login` moved to `GET /auth/me` (SEC3-8, REL3-19): it ran on
    # every request, before any role check — a Postgres upsert per API
    # call, and any realm user's token created an `operators` row.

    bootstrapper = request.app.state.bootstrapper
    await bootstrapper.maybe_bootstrap(identity)

    return CurrentPrincipal(
        identity=identity,
        kind="operator",
        claims={"sub": payload.get("sub"), "email": payload.get("email")},
    )


def client_network(request: Request) -> str:
    """
    The caller's network for lockout keying (SEC3-13): the /24 for IPv4,
    the /64 for IPv6 (one host usually owns a whole /64). `"unknown"` when
    the peer address isn't an IP.

    Behind a reverse proxy, run uvicorn with `--proxy-headers` and
    `--forwarded-allow-ips=<proxy>` so `request.client` is the real
    caller. Otherwise every request shares the proxy's network and the
    lockout falls back to being per account.
    """
    host = request.client.host if request.client else ""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return "unknown"
    prefix = 24 if ip.version == 4 else 64
    return str(ipaddress.ip_network(f"{ip}/{prefix}", strict=False))


async def _authenticate_service_account(
    request: Request, token: str, account_id: str
) -> CurrentPrincipal:
    # account_id is already known-non-None here — the sole call site
    # (get_current_principal) only takes this branch after confirming
    # parse_account_id(token) matched, so re-parsing/re-checking it here
    # would be dead code.

    # CP-16: checked *before* touching the store/argon2 — a locked-out
    # id is refused immediately, without doing the (deliberately
    # expensive, see `security._HASHER`) verify work on every attempt.
    #
    # SEC3-13: keyed on (account id, client network), not the account id
    # alone. SA ids are visible to every auditor and embedded in every
    # secret, so an id-only lockout let anyone keep a CI/deploy SA at 429
    # indefinitely with five bad requests every window. Now a brute-force
    # source only locks itself out; the SA keeps working from its own
    # network. (Secrets carry 256 random bits, so spreading guesses across
    # networks doesn't make brute force practical.)
    rate_limiter = request.app.state.service_account_rate_limiter
    limiter_key = f"{account_id}|{client_network(request)}"
    if await rate_limiter.is_locked_out(limiter_key):
        raise HTTPException(
            status_code=429,
            detail="Too many failed authentication attempts for this service account "
            "— try again later",
        )

    store = request.app.state.service_account_store
    record = await store.get(account_id)
    if record is None:
        # Unknown id: not recorded as a failed attempt (SEC3-9) — there's
        # no account to lock, and recording it let anyone grow the
        # in-memory limiter without bound under ids of their choosing.
        raise AuthenticationError("Invalid or revoked service-account secret")
    if record.is_revoked or not await _verify_cached(token, record.secret_hash):
        await rate_limiter.record_failure(limiter_key)
        if await rate_limiter.is_locked_out(limiter_key):
            # Alertable (SEC3-13): one structured warning per lockout.
            logger.warning(
                json.dumps(
                    {
                        "event": "service_account_lockout",
                        "service_account_id": account_id,
                        "client_network": client_network(request),
                    }
                )
            )
        raise AuthenticationError("Invalid or revoked service-account secret")

    await rate_limiter.record_success(limiter_key)
    await _touch_last_used_throttled(store, record)

    # Keyed on the immutable account id, never the name (SEC3-2): names
    # are reusable after revoke, so a name-keyed principal let a newly
    # created SA silently inherit a revoked SA's RBAC grants. The type
    # (`service_account`) is one the RBAC model actually defines
    # (SEC3-3) — the old `service:` prefix was rejected by real OpenFGA.
    identity = Identity(
        id=service_account_principal(record.id),
        attributes={
            "kind": "service_account",
            "scopes": record.scopes,
            "service_account_id": record.id,
            "name": record.name,
        },
    )
    return CurrentPrincipal(identity=identity, kind="service_account", scopes=tuple(record.scopes))


#: Successful verifications, keyed on `(sha256(token), stored hash)`
#: (REL3-13). Argon2 is deliberately expensive (~25 ms) and used to run on
#: the event loop for *every* service-account request, stalling every
#: other request. Including the stored hash in the key means a rotate
#: or revoke (both replace `secret_hash`; revoke also sets `revoked_at`,
#: checked before this) invalidates entries immediately on every replica,
#: since the record is still read from Postgres on each request — no TTL
#: window in which a revoked secret keeps working. Bounded LRU.
_VERIFIED: OrderedDict[tuple[str, str], None] = OrderedDict()
_VERIFIED_MAX = 1024

#: `last_used_at` is informational — writing it on every request was a
#: Postgres UPDATE per API call (REL3-13).
_TOUCH_INTERVAL = timedelta(minutes=1)


async def _verify_cached(token: str, secret_hash: str) -> bool:
    key = (hashlib.sha256(token.encode()).hexdigest(), secret_hash)
    if key in _VERIFIED:
        _VERIFIED.move_to_end(key)
        return True
    # Off the event loop: argon2 is CPU-bound by design.
    if not await anyio.to_thread.run_sync(verify_secret, token, secret_hash):
        return False
    _VERIFIED[key] = None
    while len(_VERIFIED) > _VERIFIED_MAX:
        _VERIFIED.popitem(last=False)
    return True


async def _touch_last_used_throttled(store, record) -> None:
    last_used = getattr(record, "last_used_at", None)
    if isinstance(last_used, datetime):
        now = datetime.now(last_used.tzinfo or UTC)
        if last_used.tzinfo is None:
            now = now.replace(tzinfo=None)
        if now - last_used < _TOUCH_INTERVAL:
            return
    await store.touch_last_used(record.id)


async def get_current_principal(request: Request) -> CurrentPrincipal:
    """
    Resolve the caller from `Authorization: Bearer <token>`.

    Dispatch between the two credential shapes is unambiguous and cheap:
    a service-account secret always starts with `security.SECRET_PREFIX`
    (an operator's OIDC JWT never does — JWTs are `.`-delimited base64,
    never that literal prefix), so there's no need to try one path,
    catch a failure, and fall back to the other.

    Stashes the resolved principal on `request.state.principal` — not
    used by this module itself, but read by
    `logging_middleware.install_request_logging()` (CP-18) so a request
    log line can attribute the acting identity without every route
    needing to plumb it through separately.
    """
    token = _bearer_token(request)
    try:
        account_id = parse_account_id(token)
    except MalformedServiceAccountToken as exc:
        raise AuthenticationError("Invalid or revoked service-account secret") from exc
    if account_id is not None:
        principal = await _authenticate_service_account(request, token, account_id)
    else:
        principal = await _authenticate_operator(request, token)

    request.state.principal = principal
    return principal


def _validate_scope_declaration(scope: Scope | str) -> None:
    """Fail at import time (route definition), not request time, if a
    route declares something that isn't a real scope."""
    if scope != ANY_PRINCIPAL and scope not in Scope.__members__.values():
        raise ValueError(f"Unknown scope {scope!r} — must be a `Scope` member or ANY_PRINCIPAL")


def check_service_account_scope(principal: CurrentPrincipal, required_scope: Scope | str) -> None:
    """Deny a service account that doesn't hold `required_scope`. Every
    route must name a scope (SEC3-1) — there is no "no scope required"
    value except `ANY_PRINCIPAL`, used only by self-introspection."""
    if principal.kind != "service_account" or required_scope == ANY_PRINCIPAL:
        return
    if required_scope not in principal.scopes:
        raise AuthorizationDenied(
            f"service account {principal.identity.id!r} is missing required scope "
            f"{required_scope!r}"
        )


async def _check_rbac(
    request: Request, principal: CurrentPrincipal, min_relation: str, resource: Resource
) -> None:
    rbac_authz = request.app.state.rbac_authz
    allowed = await rbac_authz.can(min_relation, principal.identity, resource)
    if not allowed:
        raise AuthorizationDenied(
            f"{principal.identity.id!r} does not hold {min_relation!r} (or higher) on "
            f"{resource.to_fga_object()!r}"
        )


def require_system_role(min_relation: str, *, scope: Scope | str):
    """
    FastAPI dependency: caller must hold `min_relation` (or anything
    above it in `ROLE_CHAIN` — union semantics already make "holds
    `owner`" imply "holds `viewer`", so a plain `can(min_relation, ...)`
    check is all this needs) on the single `system:default` object.
    """
    if min_relation not in ROLE_CHAIN:
        raise ValueError(f"Unknown role {min_relation!r} — must be one of {ROLE_CHAIN}")
    _validate_scope_declaration(scope)

    async def dependency(request: Request) -> CurrentPrincipal:
        principal = await get_current_principal(request)
        check_service_account_scope(principal, scope)
        resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
        await _check_rbac(request, principal, min_relation, resource)
        return principal

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


def require_tenant_role(
    min_relation: str,
    *,
    tenant_path_param: str = "tenant_id",
    scope: Scope | str,
):
    """
    FastAPI dependency: caller must hold `min_relation` (or higher) on
    `tenant:<tenant_id>`, where `tenant_id` comes from the route's own
    path parameter (`tenant_path_param`) — e.g. `@app.get("/tenants/{tenant_id}/...")`.

    A `system`-scoped role also satisfies a tenant check *if* the
    deployment models it that way — this implementation deliberately does
    NOT auto-imply that (a `system#admin` does not automatically pass a
    `tenant#admin` check) to keep the two scopes independent and
    explicit; grant a role on the specific `tenant:<id>` object for every
    tenant an operator should administer. (A future `Tenant` relation
    could add `from_parent`-style inheritance from `system` if that
    turns out to be the common case — not done here since it isn't
    asked for and would need its own explicit design.)
    """
    if min_relation not in ROLE_CHAIN:
        raise ValueError(f"Unknown role {min_relation!r} — must be one of {ROLE_CHAIN}")
    _validate_scope_declaration(scope)

    async def dependency(request: Request) -> CurrentPrincipal:
        principal = await get_current_principal(request)
        check_service_account_scope(principal, scope)
        tenant_id = request.path_params[tenant_path_param]
        resource = Resource(type=Tenant.type, id=tenant_id)
        await _check_rbac(request, principal, min_relation, resource)
        return principal

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


def require_tenant_admin_or_system_owner(
    *, tenant_path_param: str = "tenant_id", scope: Scope | str
):
    """
    FastAPI dependency for the one action CP-4 explicitly gates on either
    scope: deprovisioning a tenant is destructive enough that both "that
    tenant's own admin" and "the deployment's system owner" should be
    able to do it, without requiring the latter to also hold an explicit
    per-tenant grant (see `require_tenant_role`'s docstring on why the
    two scopes don't imply each other everywhere else).
    """
    _validate_scope_declaration(scope)

    async def dependency(request: Request) -> CurrentPrincipal:
        principal = await get_current_principal(request)
        check_service_account_scope(principal, scope)

        rbac_authz = request.app.state.rbac_authz
        tenant_id = request.path_params[tenant_path_param]
        tenant_resource = Resource(type=Tenant.type, id=tenant_id)
        system_resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)

        if await rbac_authz.can("admin", principal.identity, tenant_resource):
            return principal
        if await rbac_authz.can("owner", principal.identity, system_resource):
            return principal

        raise AuthorizationDenied(
            f"{principal.identity.id!r} holds neither tenant:{tenant_id}#admin nor system#owner"
        )

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


def require_tenant_role_from_query(
    min_relation: str,
    *,
    query_param: str = "tenant_id",
    scope: Scope | str,
):
    """
    Same as `require_tenant_role`, but for the one route (`POST
    /models/sync`, CP-6) whose target tenant is a query parameter rather
    than a path segment — there's no single-tenant path to pull a
    `tenant_id` path param from there.
    """
    if min_relation not in ROLE_CHAIN:
        raise ValueError(f"Unknown role {min_relation!r} — must be one of {ROLE_CHAIN}")
    _validate_scope_declaration(scope)

    async def dependency(request: Request) -> CurrentPrincipal:
        principal = await get_current_principal(request)
        check_service_account_scope(principal, scope)
        tenant_id = request.query_params.get(query_param)
        if not tenant_id:
            raise InvalidAuthzRequest(f"{query_param!r} query parameter is required")
        resource = Resource(type=Tenant.type, id=tenant_id)
        await _check_rbac(request, principal, min_relation, resource)
        return principal

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


def require_system_or_tenant_role_from_query(
    min_relation: str,
    *,
    query_param: str = "tenant_id",
    scope: Scope | str,
):
    """
    FastAPI dependency for a route whose scope is optionally narrowed by
    a `tenant_id` query parameter (e.g. `GET /audit-logs?tenant_id=...`):
    when `tenant_id` is given, the caller must hold `min_relation` on
    that specific `tenant:<id>`; when it's omitted (an unscoped,
    across-every-tenant view), the caller must hold `min_relation` at
    `system` scope instead. This is the one place the two scopes *do*
    compose (contrast `require_tenant_role`'s docstring on why they
    otherwise don't) — an unscoped query is inherently a system-wide
    view, not a claim about any one tenant.
    """
    if min_relation not in ROLE_CHAIN:
        raise ValueError(f"Unknown role {min_relation!r} — must be one of {ROLE_CHAIN}")
    _validate_scope_declaration(scope)

    async def dependency(request: Request) -> CurrentPrincipal:
        principal = await get_current_principal(request)
        check_service_account_scope(principal, scope)
        tenant_id = request.query_params.get(query_param)
        resource = (
            Resource(type=Tenant.type, id=tenant_id)
            if tenant_id
            else Resource(type=System.type, id=SYSTEM_OBJECT_ID)
        )
        await _check_rbac(request, principal, min_relation, resource)
        return principal

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


def authenticated(*, scope: Scope | str):
    """
    FastAPI dependency for routes that authenticate the caller and
    enforce the service-account scope, but run their own RBAC logic
    in-route (e.g. `POST /operators/roles`, whose target resource comes
    from the request body). Use this instead of `get_current_principal`
    directly in a route — that function performs no scope check, so a
    route depending on it alone would let any service account through
    regardless of scopes (SEC3-1; enforced by
    `tests/control_plane/test_route_scopes.py`).
    """
    _validate_scope_declaration(scope)

    async def dependency(
        principal: CurrentPrincipal = Depends(get_current_principal),
    ) -> CurrentPrincipal:
        check_service_account_scope(principal, scope)
        return principal

    dependency.required_scope = scope  # type: ignore[attr-defined]  # see test_route_scopes.py
    return dependency


async def effective_system_role(rbac_authz, identity: Identity) -> str | None:
    """
    The highest role (first hit walking `ROLE_CHAIN` from `owner` down)
    `identity` holds on `system:default`, or `None` if none. Used by
    `GET /auth/me` to report "effective roles" without the caller having
    to issue one check per role name themselves.
    """
    resource = Resource(type=System.type, id=SYSTEM_OBJECT_ID)
    # Concurrently (REL3-19): these used to be up to five sequential
    # OpenFGA round trips on every panel page load.
    held = await asyncio.gather(*(rbac_authz.can(role, identity, resource) for role in ROLE_CHAIN))
    return next((role for role, ok in zip(ROLE_CHAIN, held, strict=True) if ok), None)

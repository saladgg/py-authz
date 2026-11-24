"""
The closed set of service-account scopes (SEC3-1).

A service account's effective permission on any route is the
intersection of two independent checks:

    1. **scope** — a coarse, self-declared capability ceiling fixed at
       creation time ("this credential may only ever read audit logs"),
       checked first and cheaply, without touching OpenFGA;
    2. **RBAC role** — the same `authz.can(...)` check an operator gets,
       against the dogfooded RBAC store.

Before SEC3-1, scopes were free-form strings and no production route ever
declared one, so (1) was a no-op: an SA created with ``scopes=[]`` could
call every route its RBAC role allowed. Now every auth dependency factory
in `auth.py` *requires* a `scope=` argument (there's no default to
forget), scopes are validated against this enum on create, and an SA
principal is denied on any route that doesn't name a scope it holds.

Operators (humans) are never scope-checked — scopes are a property of a
machine credential, not of a person; an operator's ceiling is their RBAC
role alone.
"""

from enum import StrEnum


class Scope(StrEnum):
    TENANTS_READ = "tenants:read"
    TENANTS_WRITE = "tenants:write"
    MODELS_READ = "models:read"
    MODELS_WRITE = "models:write"
    MIGRATIONS_READ = "migrations:read"
    MIGRATIONS_WRITE = "migrations:write"
    TUPLES_READ = "tuples:read"
    TUPLES_WRITE = "tuples:write"
    AUDIT_READ = "audit:read"
    CACHE_READ = "cache:read"
    CACHE_WRITE = "cache:write"
    METRICS_READ = "metrics:read"
    SERVICE_ACCOUNTS_READ = "service_accounts:read"
    SERVICE_ACCOUNTS_WRITE = "service_accounts:write"
    OPERATORS_READ = "operators:read"
    OPERATORS_WRITE = "operators:write"


#: Sentinel for the one route any authenticated principal may call
#: regardless of scopes — `GET /auth/me`, a principal introspecting
#: itself. Deliberately *not* a `Scope` member, so it can never be
#: granted to (or validated onto) a service account.
ANY_PRINCIPAL = "__any_principal__"


GRANTABLE_SCOPES: tuple[str, ...] = tuple(s.value for s in Scope)

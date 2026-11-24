"""
SEC3-1 guard: every authenticated control-plane route declares a
service-account scope.

Before SEC3-1 no production route passed a scope, so an SA's scopes were
never checked anywhere — a credential created with `scopes=[]` could call
every route its RBAC role allowed. The dependency factories in `auth.py`
now *require* `scope=` and tag the dependency they return with
`required_scope`. This test walks the real app's dependency graph and
fails if any route under `/api/v1` authenticates a caller without passing
through one of those tagged dependencies — e.g. a new route that depends
on `get_current_principal` directly (which performs no scope check).
"""

import pytest
from fastapi.routing import APIRoute

from py_authz.control_plane.app import API_PREFIX, API_ROUTERS
from py_authz.control_plane.auth import get_current_principal
from py_authz.control_plane.scopes import ANY_PRINCIPAL, Scope

#: The only route allowed to accept any principal regardless of scopes.
_ANY_PRINCIPAL_ROUTES = {("GET", "/api/v1/auth/me")}


def _calls(dependant):
    if dependant.call is not None:
        yield dependant.call
    for sub in dependant.dependencies:
        yield from _calls(sub)


def _api_routes():
    for router in API_ROUTERS:
        for route in router.routes:
            assert isinstance(route, APIRoute)
            for method in sorted(route.methods):
                yield method, route


def _full_path(route) -> str:
    return f"{API_PREFIX}{route.path}"


def _route_ids():
    return [f"{m} {_full_path(r)}" for m, r in _api_routes()]


@pytest.mark.parametrize(("method", "route"), list(_api_routes()), ids=_route_ids())
def test_every_authenticated_route_declares_a_scope(method, route):
    calls = list(_calls(route.dependant))
    scopes = [c.required_scope for c in calls if hasattr(c, "required_scope")]

    assert scopes, (
        f"{method} {route.path} has no scope-declaring auth dependency — use one of the "
        "`require_*`/`authenticated` factories in control_plane/auth.py"
    )
    for scope in scopes:
        if scope == ANY_PRINCIPAL:
            assert (method, _full_path(route)) in _ANY_PRINCIPAL_ROUTES, (
                f"{method} {_full_path(route)} uses ANY_PRINCIPAL, which is reserved for "
                "self-introspection"
            )
        else:
            assert scope in set(Scope)


@pytest.mark.parametrize(("method", "route"), list(_api_routes()), ids=_route_ids())
def test_no_route_depends_on_the_unscoped_principal_resolver_directly(method, route):
    """`get_current_principal` may appear only *underneath* a scoped
    dependency (as `authenticated()`'s own sub-dependency), never as a
    route's direct dependency."""
    direct = [d.call for d in route.dependant.dependencies]
    assert get_current_principal not in direct, f"{method} {route.path}"


def test_the_guard_actually_sees_routes():
    """Guard against this test silently parametrizing over nothing."""
    assert len(list(_api_routes())) >= 25

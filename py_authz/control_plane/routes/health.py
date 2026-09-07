"""GET /health, GET /metrics (CP-10)."""

from fastapi import APIRouter, Depends

from py_authz.control_plane.auth import require_system_role
from py_authz.control_plane.deps import get_metrics, get_product_fga_client
from py_authz.core.exceptions import ExternalServiceError

#: Mounted unversioned, at the app root, with no auth dependency — a load
#: balancer/orchestrator probe has no operator session or service-account
#: credential to present (see `health()`'s own docstring).
health_router = APIRouter(tags=["health"])

#: Mounted under `/api/v1` like every other authenticated route.
router = APIRouter(tags=["health"])


@health_router.get("/health")
async def health(fga_client=Depends(get_product_fga_client)) -> dict:
    """
    Unauthenticated (the one route in this API that is — a load
    balancer/orchestrator health check has no operator session or
    service-account credential to present) reachability probe. Attempts
    a real, cheap OpenFGA call (`get_latest_model()` against the product
    OpenFGA instance's `store_id`-less client would 404 without one, so
    this uses the RBAC store — always guaranteed to exist once the
    control-plane API itself started) rather than only reporting process
    liveness.
    """
    checks: dict[str, str] = {}
    try:
        await fga_client.get_latest_model()
        checks["openfga"] = "ok"
    except ExternalServiceError as exc:
        checks["openfga"] = f"unreachable: {exc}"

    healthy = all(v == "ok" for v in checks.values())
    return {"status": "ok" if healthy else "degraded", "checks": checks}


@router.get("/metrics", dependencies=[Depends(require_system_role("auditor"))])
async def get_metrics_endpoint(metrics=Depends(get_metrics)) -> dict:
    """
    Aggregated `core/metrics.py` counters/durations, in a shape a
    dashboard (or a scrape-based exporter sitting in front of this) can
    render directly. `durations` reports count/sum/avg rather than every
    raw observation — `Metrics.observe()`'s own ring buffer already caps
    how many it keeps (see REL2-5), but there's no reason to ship all of
    them over the wire when three numbers say as much for a dashboard tile.
    """
    duration_summaries = {}
    for name, values in metrics.durations.items():
        duration_summaries[name] = {
            "count": len(values),
            "sum": sum(values),
            "avg": (sum(values) / len(values)) if values else 0.0,
        }
    return {"counters": dict(metrics.counters), "durations": duration_summaries}

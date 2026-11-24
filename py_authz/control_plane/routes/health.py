"""GET /livez, /readyz, /health (probes) and GET /metrics (CP-10)."""

import asyncio
import logging

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from py_authz.control_plane.auth import require_system_role
from py_authz.control_plane.deps import get_metrics, get_readiness_checks
from py_authz.control_plane.scopes import Scope

logger = logging.getLogger("py_authz.control_plane.health")

#: Per-check ceiling. Every OpenFGA check client is built with
#: `max_retries=0`, so this bounds the whole probe too (checks run
#: concurrently).
CHECK_TIMEOUT_SECONDS = 1.0

#: Mounted unversioned, at the app root, with no auth dependency — a load
#: balancer/orchestrator probe has no operator session or service-account
#: credential to present.
health_router = APIRouter(tags=["health"])

#: Mounted under `/api/v1` like every other authenticated route.
router = APIRouter(tags=["health"])


@health_router.get("/livez")
async def livez() -> dict:
    """Liveness: the process is up and serving. Checks no dependencies —
    a dependency outage should take the instance out of rotation
    (`/readyz`), not get it restarted."""
    return {"status": "ok"}


async def _run_check(name: str, check) -> tuple[str, bool]:
    try:
        await asyncio.wait_for(check(), timeout=CHECK_TIMEOUT_SECONDS)
        return name, True
    except Exception:  # noqa: BLE001 — any failure means "not ready"
        logger.warning("readiness check %r failed", name, exc_info=True)
        return name, False


async def _readiness(checks: dict) -> JSONResponse:
    results = await asyncio.gather(*(_run_check(n, c) for n, c in checks.items()))
    report = {name: ("ok" if ok else "unavailable") for name, ok in results}
    ready = all(ok for _, ok in results)
    return JSONResponse(
        status_code=200 if ready else 503,
        content={"status": "ok" if ready else "unavailable", "checks": report},
    )


@health_router.get("/readyz")
async def readyz(checks: dict = Depends(get_readiness_checks)) -> JSONResponse:
    """
    Readiness (REL3-7): Postgres, Redis (when configured) and OpenFGA —
    the product instance, plus the RBAC instance when it's a different
    URL — checked concurrently, each bounded to `CHECK_TIMEOUT_SECONDS`
    with no retries. **503** if any fails, so a load balancer stops
    routing to an instance that can't serve.

    Before REL3-7 the only probe was `/health`: it always returned 200
    (a degraded status lived only in the body), checked neither Postgres
    nor Redis, probed the RBAC store under the name "product", went
    through the retrying client (6s+ worst case), and echoed raw
    exception text to unauthenticated callers. Failure details are now
    logged server-side only.
    """
    return await _readiness(checks)


@health_router.get("/health")
async def health(checks: dict = Depends(get_readiness_checks)) -> JSONResponse:
    """Backwards-compatible alias of `/readyz` — note it now returns 503
    (not 200 with a "degraded" body) when a dependency is down."""
    return await _readiness(checks)


@router.get(
    "/metrics", dependencies=[Depends(require_system_role("auditor", scope=Scope.METRICS_READ))]
)
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

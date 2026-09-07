"""
Structured request logging for the control-plane API (CP-18) — matches
`core/logging.py`'s existing JSON-line convention (`logger.info(json.dumps({...}))`,
already used throughout this library for `provision_start`/`migration_success`/etc.)
so operator/service-account actions land in the same log pipeline an
adopter's other `py-authz` logs already go to, rather than a separately-
shaped access log.

Deliberately logs only method/path/status/duration/acting-principal —
never headers, query strings, or request/response bodies. That's not an
oversight: a request body can be a service-account creation payload, a
manual grant/revoke `reason`, or (on the auth path itself) an
`Authorization` header carrying a live bearer credential — none of that
belongs in a log line (see CP-17's secrets-handling pass, which the same
principle applies to).
"""

import json
import logging
import time

from fastapi import FastAPI, Request

logger = logging.getLogger("py_authz.control_plane.requests")


def install_request_logging(app: FastAPI) -> None:
    """Register the request-logging middleware on `app`. Split out from
    `app.py`'s own wiring so it's independently testable/reusable."""

    @app.middleware("http")
    async def _log_requests(request: Request, call_next):
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            _log(request, status_code=None, start=start, failed=True)
            raise

        _log(request, status_code=response.status_code, start=start, failed=False)
        return response


def _log(request: Request, *, status_code: int | None, start: float, failed: bool) -> None:
    duration_ms = round((time.monotonic() - start) * 1000, 2)

    # Set by `auth.get_current_principal()` on a successful authentication
    # — absent for `/health` (unauthenticated) and for a request that
    # failed authentication before a principal was ever resolved.
    principal = getattr(request.state, "principal", None)

    payload = {
        "event": "control_plane_request",
        "method": request.method,
        "path": request.url.path,
        "status_code": status_code,
        "duration_ms": duration_ms,
        "principal": principal.identity.id if principal else None,
        "principal_kind": principal.kind if principal else None,
    }

    if failed or (status_code is not None and status_code >= 500):
        logger.error(json.dumps(payload))
    else:
        logger.info(json.dumps(payload))

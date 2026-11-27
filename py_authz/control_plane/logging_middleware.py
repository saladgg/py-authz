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
import re
import time
import uuid

from fastapi import FastAPI, Request

from py_authz.core.context import get_request_id, set_request_id

logger = logging.getLogger("py_authz.control_plane.requests")

#: A caller-supplied `X-Request-ID` is reused only if it looks like an id,
#: so it can't inject arbitrary text into logs or response headers.
_SAFE_REQUEST_ID = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


def _request_id_for(request: Request) -> str:
    supplied = request.headers.get("x-request-id", "")
    return supplied if _SAFE_REQUEST_ID.fullmatch(supplied) else str(uuid.uuid4())


def install_request_logging(app: FastAPI) -> None:
    """Register the request-logging middleware on `app`. Split out from
    `app.py`'s own wiring so it's independently testable/reusable."""

    @app.middleware("http")
    async def _log_requests(request: Request, call_next):
        # REL3-24: one id per request, shared by this log line, every
        # library log line emitted while handling it (`AuthzEngine` reads
        # `get_request_id()`), and the `X-Request-ID` response header.
        set_request_id(_request_id_for(request))
        start = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            _log(request, status_code=None, start=start, failed=True)
            _record(request, start=start, failed=True)
            raise

        _log(request, status_code=response.status_code, start=start, failed=False)
        _record(request, start=start, failed=response.status_code >= 500)
        response.headers["X-Request-ID"] = get_request_id() or ""
        return response


def _record(request: Request, *, start: float, failed: bool) -> None:
    """Request count, 5xx count and duration (REL3-24) into `app.state.metrics`."""
    metrics = getattr(request.app.state, "metrics", None)
    if metrics is None:
        return
    metrics.incr("control_plane_requests_total")
    if failed:
        metrics.incr("control_plane_request_errors_total")
    metrics.observe("control_plane_request_duration_ms", (time.monotonic() - start) * 1000)


def _log(request: Request, *, status_code: int | None, start: float, failed: bool) -> None:
    duration_ms = round((time.monotonic() - start) * 1000, 2)

    # Set by `auth.get_current_principal()` on a successful authentication
    # — absent for `/health` (unauthenticated) and for a request that
    # failed authentication before a principal was ever resolved.
    principal = getattr(request.state, "principal", None)

    payload = {
        "event": "control_plane_request",
        "request_id": get_request_id(),
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

"""
`AuthzError` -> HTTP status mapping (CP-1), mirroring the CLI's
`_EXIT_CODES` table (`cli/main.py:29`) instead of inventing a parallel
convention (see the architecture doc's open questions, §3) — same
"most-specific-first" ordering rule applies here for the same reason:
`ExternalServiceError`/`ConfigurationError`/etc. all inherit from
`AuthzError`, so a general check earlier in the list would shadow every
more specific one after it.
"""

import logging
import uuid

from fastapi import Request
from fastapi.responses import JSONResponse

from py_authz.core.context import get_request_id
from py_authz.core.exceptions import (
    AuthenticationError,
    AuthorizationDenied,
    AuthzError,
    ConfigurationError,
    ExternalServiceError,
    InvalidAuthzRequest,
    TenantNotFoundError,
)

logger = logging.getLogger("py_authz.control_plane")

# Ordered most-specific-first — see module docstring.
_STATUS_CODES: list[tuple[type[AuthzError], int]] = [
    (AuthenticationError, 401),
    (AuthorizationDenied, 403),
    (TenantNotFoundError, 404),
    (InvalidAuthzRequest, 400),
    (ExternalServiceError, 503),
    (ConfigurationError, 500),  # a server misconfiguration, not the caller's fault
]


def status_code_for(exc: AuthzError) -> int:
    for exc_type, code in _STATUS_CODES:
        if isinstance(exc, exc_type):
            return code
    return 500  # any other AuthzError


async def authz_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """
    Registered on the FastAPI app for `AuthzError` (see `app.py`) — a
    known, categorized failure becomes a JSON body with a stable `error`
    field and a status code an automated caller can branch on, instead of
    an unhandled-exception 500 with a raw traceback. Anything that isn't
    an `AuthzError` (a genuine bug) is deliberately left to FastAPI's own
    default handling, so it still surfaces for debugging rather than
    being silently reclassified as a generic client/server error.

    Typed as `exc: Exception` (not `AuthzError`) only because Starlette's
    own `add_exception_handler()` signature requires it — `app.py`
    registers this handler for `AuthzError` specifically, so Starlette
    only ever dispatches an `AuthzError` instance here (mirrors
    `core/enforcement.py`'s own `assert self.cache is not None` — a
    type-narrowing invariant already guaranteed by the caller, not
    re-derived here).
    """
    assert isinstance(exc, AuthzError)  # noqa: S101 — see docstring
    status_code = status_code_for(exc)
    if status_code >= 500:
        # SEC3-11: a 5xx's message is about *our* internals (a JWKS URL,
        # an OpenFGA path containing the RBAC store id, a config value)
        # and was echoed to the caller — including unauthenticated ones.
        # Log it in full; return a generic message plus an id to find it.
        incident_id = get_request_id() or uuid.uuid4().hex
        logger.exception("control-plane request failed (incident %s)", incident_id, exc_info=exc)
        return JSONResponse(
            status_code=status_code,
            content={
                "error": type(exc).__name__,
                "detail": _GENERIC_5XX.get(status_code, "Internal error"),
                "incident_id": incident_id,
            },
        )
    logger.info("control-plane request denied: %s: %s", type(exc).__name__, exc, exc_info=False)
    return JSONResponse(
        status_code=status_code,
        content={"error": type(exc).__name__, "detail": str(exc)},
    )


_GENERIC_5XX = {
    500: "Internal error",
    503: "A dependency is unavailable — try again shortly",
}

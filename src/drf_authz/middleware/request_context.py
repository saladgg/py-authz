from __future__ import annotations
from typing import Callable
import uuid

from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth.models import AnonymousUser


class RequestContextMiddleware(MiddlewareMixin):
    """Middleware that ensures request.user and request.context always exist.

    - Guarantees ``request.user`` is set (AnonymousUser if missing).
    - Initializes ``request.context`` as a dict for tenant/org/request metadata.
    - Injects a per-request ``request_id`` useful for logging/tracing.

    Place this middleware *after* Django's AuthenticationMiddleware when used
    with session or OIDC authentication.
    """

    def process_request(self, request):  # noqa: D401
        # Ensure request.user always exists
        if not hasattr(request, "user") or request.user is None:
            request.user = AnonymousUser()

        # Ensure request.context dict exists
        if not hasattr(request, "context"):
            request.context = {}

        # Add per-request unique ID (useful for logs & correlation tracing)
        if "request_id" not in request.context:
            request.context["request_id"] = str(uuid.uuid4())

        return None

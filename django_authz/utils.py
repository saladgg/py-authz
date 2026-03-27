from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from django.http import HttpRequest


def get_bearer_token(request: HttpRequest) -> str | None:
    """Extract a Bearer token from the Authorization header."""
    auth = request.META.get("HTTP_AUTHORIZATION", "")
    if not auth:
        return None
    kind, _, token = auth.partition(" ")
    if kind.lower() == "bearer" and token:
        return token
    return None


def merge_dicts(*maps: Mapping[str, Any]) -> dict[str, Any]:
    """Merge multiple mappings left-to-right; later values win on duplicate keys."""
    out: dict[str, Any] = {}
    for m in maps:
        out.update(dict(m))
    return out

from __future__ import annotations

from collections.abc import Callable
from functools import wraps

from django.core.exceptions import PermissionDenied
from django.http import Http404

from django_authz.authorization.openfga import OpenFGAClient
from django_authz.conf import CONFIG


def fga_requires(
    object_type: str,
    relation: str,
    object_id_kwarg: str = "pk",
    user_fmt: Callable | None = None,
):
    """Decorate a Django view method to enforce an FGA check before execution.

    Args:
        object_type: FGA object type, e.g., "project".
        relation: FGA relation, e.g., "viewer".
        object_id_kwarg: name of the URL kwarg to read object id from.
        user_fmt: optional function(request, *a, **kw) -> user string
            (default: "user:{request.user.pk}")
    """

    def decorator(view_fn):
        @wraps(view_fn)
        def _wrapped(self, request, *args, **kwargs):
            object_id = kwargs.get(object_id_kwarg)
            if not object_id:
                raise Http404(f"Missing {object_id_kwarg}")
            user_str = user_fmt(request, *args, **kwargs) if user_fmt else f"user:{request.user.pk}"
            client = OpenFGAClient(
                api_url=CONFIG.OPENFGA_API_URL,
                store_id=CONFIG.OPENFGA_STORE_ID,
            )
            allowed = client.check(
                user=user_str, relation=relation, object_=f"{object_type}:{object_id}"
            )
            if not allowed:
                raise PermissionDenied("You are not allowed to perform this action.")
            return view_fn(self, request, *args, **kwargs)

        return _wrapped

    return decorator

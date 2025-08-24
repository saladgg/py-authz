from __future__ import annotations
from functools import wraps
from typing import Callable, Optional
from django.http import Http404
from rest_framework.exceptions import PermissionDenied
from drf_authz.authorization import OpenFGAClient


def fga_requires(object_type: str, relation: str, object_id_kwarg: str = "pk", user_fmt: Optional[Callable] = None):
    """Decorate a DRF view method to enforce FGA check before execution.

    Args:
        object_type: FGA object type, e.g., "project".
        relation: FGA relation, e.g., "viewer".
        object_id_kwarg: name of the URL kwarg to read object id from.
        user_fmt: optional function(request, *a, **kw) -> user string (default: "user:{request.user.pk}")
    """

    def decorator(view_fn):
        @wraps(view_fn)
        def _wrapped(self, request, *args, **kwargs):
            object_id = kwargs.get(object_id_kwarg)
            if not object_id:
                raise Http404(f"Missing {object_id_kwarg}")
            user_str = user_fmt(request, *args, **kwargs) if user_fmt else f"user:{request.user.pk}"
            client = OpenFGAClient()
            allowed = client.check(user=user_str, object_type=object_type, relation=relation, object_id=str(object_id))
            if not allowed:
                raise PermissionDenied("You are not allowed to perform this action.")
            return view_fn(self, request, *args, **kwargs)

        return _wrapped

    return decorator

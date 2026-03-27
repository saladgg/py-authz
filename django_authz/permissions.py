"""
Django permission helpers powered by OpenFGA.

Provides a CBV mixin and a function-based view decorator for enforcing
fine-grained authorization via an OpenFGA client.
"""

from django.contrib.auth.mixins import AccessMixin

from django_authz.authorization.base import BaseOpenFGAClient


class FGAPermissionMixin(AccessMixin):
    """Django CBV mixin that enforces an OpenFGA object-level permission check.

    Attributes:
        fga_client (BaseOpenFGAClient): The OpenFGA client instance.
        fga_relation (str): The relation/action required (e.g., "read", "write").

    The mixin calls ``get_object()`` to resolve the target object, so it is
    intended for detail views (``DetailView``, ``UpdateView``, etc.).

    Example::

        from django_authz.permissions import FGAPermissionMixin
        from django_authz.authorization.openfga import OpenFGAClient

        client = OpenFGAClient(api_url="http://localhost:8080", store_id="store123")

        class DocumentDetail(FGAPermissionMixin, DetailView):
            model = Document
            fga_client = client
            fga_relation = "viewer"
    """

    fga_client: BaseOpenFGAClient | None = None
    fga_relation: str | None = None

    def get_fga_user(self) -> str:
        """Return the FGA user string. Override to customise (e.g. use a claim)."""
        return str(self.request.user)

    def dispatch(self, request, *args, **kwargs):
        if not self.fga_client:
            raise ValueError(
                "FGAPermissionMixin.fga_client must be set to a BaseOpenFGAClient instance."
            )
        if not self.fga_relation:
            raise ValueError("FGAPermissionMixin.fga_relation must be set (e.g., 'read', 'write').")

        obj = self.get_object()
        object_id = f"{obj.__class__.__name__}:{obj.pk}"
        if not self.fga_client.check(
            user=self.get_fga_user(), relation=self.fga_relation, object_=object_id
        ):
            return self.handle_no_permission()
        return super().dispatch(request, *args, **kwargs)

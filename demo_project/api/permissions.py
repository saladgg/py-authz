"""Custom DRF permission classes for the demo project.

These classes demonstrate how to integrate ``django_authz``'s OpenFGA client
with Django REST Framework's permission system.

``FGAPermission`` is a reusable base class: subclass it, set ``relation``, and
register your client.  The object-level check uses the object's ``pk`` attribute
as the FGA object ID.

Example usage in a view::

    class DocumentView(APIView):
        permission_classes = [IsDocumentReader]

        def get(self, request, doc_id):
            ...
"""

from rest_framework.permissions import BasePermission

from django_authz.authorization.openfga import OpenFGAClient

# Shared client instance — in production, configure via DJANGO_AUTHZ settings
# and construct lazily (or use the Policy helper from django_authz.authorization.policies).
fga_client = OpenFGAClient(
    api_url="http://localhost:8080",
    store_id="store123",
)


class FGAPermission(BasePermission):
    """DRF permission base class backed by OpenFGA.

    Subclasses must set:
      - ``client``: a :class:`~django_authz.authorization.base.BaseOpenFGAClient` instance.
      - ``object_type``: the FGA object type string (e.g. ``"doc"``).
      - ``relation``: the FGA relation to check (e.g. ``"reader"``).

    The object-level check derives the FGA object ID from ``obj.pk``.
    """

    client: OpenFGAClient = fga_client
    object_type: str = "doc"
    relation: str

    def has_permission(self, request, view) -> bool:
        """Allow authenticated users through to object-level checks."""
        return bool(request.user and request.user.is_authenticated)

    def has_object_permission(self, request, view, obj) -> bool:
        """Check the FGA relation for the authenticated user on this object."""
        user = f"user:{request.user.pk}"
        fga_object = f"{self.object_type}:{obj.pk}"
        return self.client.check(user=user, relation=self.relation, object_=fga_object)


class IsDocumentReader(FGAPermission):
    """Grants access when the user holds the ``reader`` relation on the document."""

    relation = "reader"


class IsDocumentEditor(FGAPermission):
    """Grants access when the user holds the ``editor`` relation on the document."""

    relation = "editor"

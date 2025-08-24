"""
Custom DRF permission classes powered by OpenFGA.

These permissions delegate fine-grained access checks to an OpenFGA
client that implements the BaseOpenFGAClient interface. This makes the
permission layer agnostic to whether you use the REST client
(`OpenFGAClient`) or the official SDK client (`OpenFGASDKClient`).
"""

from rest_framework.permissions import BasePermission
from drf_authz.authorization.base import BaseOpenFGAClient


class FGAPermission(BasePermission):
    """
    A DRF permission class that uses an OpenFGA client to enforce
    fine-grained authorization.

    Attributes:
        client (BaseOpenFGAClient): The OpenFGA client instance.
        relation (str): The relation/action required (e.g., "read", "write").

    Example:
        >>> from drf2auth.authorization.openfga import OpenFGAClient
        >>> client = OpenFGAClient(api_url="http://localhost:8080", store_id="store123")
        >>> class IsViewer(FGAPermission):
        ...     relation = "viewer"
        ...     client = client
    """

    client: BaseOpenFGAClient = None
    relation: str = None

    def has_object_permission(self, request, view, obj) -> bool:
        """
        Check object-level permissions via OpenFGA.

        Args:
            request: The current DRF request.
            view: The DRF view.
            obj: The object being accessed.

        Returns:
            True if access is allowed, False otherwise.
        """
        if not self.client:
            raise ValueError("FGAPermission.client must be set to a BaseOpenFGAClient instance.")
        if not self.relation:
            raise ValueError("FGAPermission.relation must be set (e.g., 'read', 'write').")

        user = str(request.user)  # Customize this if you want user.id or a specific claim
        object_id = f"{obj.__class__.__name__}:{obj.pk}"
        return self.client.check(user=user, relation=self.relation, object_=object_id)

"""High-level policy helpers for OpenFGA authorization.

:class:`Policy` wraps any :class:`~django_authz.authorization.base.BaseOpenFGAClient`
and exposes a single ``is_allowed()`` method for clean, readable permission
checks in service/business-logic code.

Example::

    from django_authz.authorization.policies import Policy, ObjectRef

    policy = Policy()  # uses DJANGO_AUTHZ settings automatically

    if policy.is_allowed(user="user:alice", relation="reader", obj=ObjectRef("doc", "42")):
        ...
"""

from __future__ import annotations

from dataclasses import dataclass

from django_authz.authorization.base import BaseOpenFGAClient


@dataclass(frozen=True)
class ObjectRef:
    """A typed reference to an FGA object.

    Attributes:
        type: The FGA object type, e.g. ``"doc"``.
        id: The FGA object identifier, e.g. ``"42"``.
    """

    type: str
    id: str


class Policy:
    """High-level policy helper; extend or override in application code.

    If *client* is not provided the constructor will build an
    :class:`~django_authz.authorization.openfga.OpenFGAClient` from
    ``DJANGO_AUTHZ`` settings (``OPENFGA_API_URL`` + ``OPENFGA_STORE_ID``
    must both be set).

    Attributes:
        client: The underlying FGA client used for authorization checks.
    """

    def __init__(self, client: BaseOpenFGAClient | None = None):
        from django_authz.authorization.openfga import OpenFGAClient
        from django_authz.conf import CONFIG

        if client is not None:
            self.client: BaseOpenFGAClient = client
        else:
            if not CONFIG.OPENFGA_API_URL or not CONFIG.OPENFGA_STORE_ID:
                raise ValueError(
                    "OPENFGA_API_URL and OPENFGA_STORE_ID must be configured "
                    "in DJANGO_AUTHZ settings, or pass an explicit client."
                )
            self.client = OpenFGAClient(
                api_url=CONFIG.OPENFGA_API_URL, store_id=CONFIG.OPENFGA_STORE_ID
            )

    def is_allowed(self, user: str, relation: str, obj: ObjectRef) -> bool:
        """Check whether *user* holds *relation* on *obj*.

        Args:
            user: FGA user string, e.g. ``"user:alice"``.
            relation: FGA relation, e.g. ``"reader"``.
            obj: Target object reference.

        Returns:
            ``True`` if the relation exists in the FGA store, ``False`` otherwise.
        """
        return self.client.check(user=user, relation=relation, object_=f"{obj.type}:{obj.id}")

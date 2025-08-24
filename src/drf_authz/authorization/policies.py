from __future__ import annotations
from dataclasses import dataclass
from drf_authz.authorization import OpenFGAClient


@dataclass(frozen=True)
class ObjectRef:
    type: str
    id: str


class Policy:
    """High-level policy helpers; extend/override in app code if needed."""

    def __init__(self, client: OpenFGAClient | None = None):
        self.client = client or OpenFGAClient()

    def is_allowed(self, user: str, relation: str, obj: ObjectRef) -> bool:
        return self.client.check(user=user, object_type=obj.type, relation=relation, object_id=obj.id)

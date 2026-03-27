"""OpenFGA relationship tuple representation.

A :class:`RelationTuple` models a single OpenFGA relationship of the form
``object_type:object_id#relation@user``, e.g. ``doc:123#reader@user:alice``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class RelationTuple:
    """Immutable representation of an OpenFGA relationship tuple.

    Attributes:
        object_type: The FGA object type, e.g. ``"doc"``.
        object_id: The FGA object identifier, e.g. ``"123"``.
        relation: The relation between the user and the object, e.g. ``"reader"``.
        user: The subject string, e.g. ``"user:alice"`` or a subject set.

    Example::

        t = RelationTuple(object_type="doc", object_id="42", relation="reader", user="user:alice")
        print(t.fga_string())  # "doc:42#reader@user:alice"
    """

    object_type: str
    object_id: str
    relation: str
    user: str  # e.g. "user:123" or a subject set like "group:eng#member"

    def fga_string(self) -> str:
        """Return the canonical OpenFGA tuple string representation.

        Format: ``<object_type>:<object_id>#<relation>@<user>``
        """
        return f"{self.object_type}:{self.object_id}#{self.relation}@{self.user}"

from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class RelationTuple:
    object_type: str
    object_id: str
    relation: str
    user: str  # e.g., "user:123" or a subject set

    def fga_string(self) -> str:
        return f"{self.object_type}:{self.object_id}#{self.relation}@{self.user}"
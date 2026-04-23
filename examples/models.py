"""
Shared authorization models used across every example.

Scenario: a small document-management app with:
    - `document`  — readable/editable/ownable
    - `folder`    — holds documents, inheritable permissions

Relations are declared with `Relation(...)` and resource classes subclass
`ResourceModel`. Every `ResourceModel` must set `type` (the OpenFGA object
type) and must be registered with the global `registry` so the model
generator emits it.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import registry


class Folder(ResourceModel):
    type = "folder"

    owner = Relation("owner")
    editor = Relation("editor", union=["owner"])
    viewer = Relation("viewer", union=["editor"])


class Document(ResourceModel):
    type = "document"

    owner = Relation("owner")
    editor = Relation("editor", union=["owner"])
    viewer = Relation("viewer", union=["editor"])


registry.register(Folder)
registry.register(Document)

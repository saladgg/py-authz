"""
Shared authorization models used across every example.

Scenario: a small document-management app with:
    - `document`  — readable/editable/ownable, and can live inside a folder
    - `folder`    — holds documents; a folder viewer is also a viewer of
                    every document inside it, via `parent`/`from_parent`
                    (OpenFGA's `tupleToUserset`)

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

    # Which folder (if any) this document lives in. Populated by writing a
    # tuple with the *folder* as `user` and the document as `object` — see
    # `seed.py`'s "document:budget" / "folder:engineering" pair.
    parent = Relation("parent", subjects=["folder"])

    # Direct grant (`this`), editor-implies-viewer (`union`), OR a viewer
    # of the parent folder (`from_parent` → `tupleToUserset`) — any one of
    # the three is sufficient. `subjects=["user"]` is explicit here because
    # `from_parent` alone would otherwise default `subjects` to `[]`
    # (see `Relation.__init__`'s docstring) and drop direct assignment.
    viewer = Relation(
        "viewer",
        union=["editor"],
        from_parent=("parent", "viewer"),
        subjects=["user"],
    )


registry.register(Folder)
registry.register(Document)

import json
from typing import Any

#: Keys whose value being an empty dict/list is semantically meaningful
#: and must survive `_strip_server_defaults` even though it looks like a
#: "zero value" — most importantly `"this": {}`, the marker for "this
#: relation supports direct assignment", and `"child": []`, a (degenerate
#: but structurally distinct) empty union/intersection/difference operand
#: list.
_PRESERVE_EVEN_IF_EMPTY = frozenset({"this", "child"})


def _strip_server_defaults(value: Any) -> Any:
    """
    Recursively drop OpenFGA-injected "zero value" noise from a model
    fetched back from the server, so it can be meaningfully compared
    against a locally generated one.

    OpenFGA stores/echoes every optional field at its protobuf zero value
    instead of omitting the key — e.g. a fetched model's
    `computedUserset` carries an `"object": ""` a locally generated one
    never has, each `directly_related_user_types` entry carries a
    `"condition": ""`, and each type's `metadata` carries `"module": ""`
    and `"source_info": null`. None of these are ever set by anything
    this library's generator produces, so comparing the raw dicts
    wholesale reports "changed" for every model, even one that round-
    tripped through OpenFGA unchanged. `this: {}` (and an empty `child`
    list) are the exceptions: their emptiness is the meaningful part of
    the schema, not a server-added default, so they're never stripped.
    """
    if isinstance(value, dict):
        cleaned = {}
        for key, sub_value in value.items():
            sub_value = _strip_server_defaults(sub_value)
            if key in _PRESERVE_EVEN_IF_EMPTY:
                cleaned[key] = sub_value
                continue
            if sub_value is None or sub_value in ("", {}, []):
                continue
            cleaned[key] = sub_value
        return cleaned

    if isinstance(value, list):
        return [_strip_server_defaults(item) for item in value]

    return value


def _canonicalize_lists(value: Any) -> Any:
    """
    Recursively sort every list's items into a stable, deterministic
    order, so two structurally-equal models that merely enumerate their
    `type_definitions`, `directly_related_user_types`, or `union`/
    `intersection` `child` operands in a different order compare equal
    (see ARCH2-11). None of these lists have order-dependent semantics in
    OpenFGA's model schema — union/intersection are commutative, and
    `type_definitions`/`directly_related_user_types` are unordered sets —
    so sorting them is always safe.

    Each item is sorted by its own normalized JSON form (`sort_keys=True`)
    rather than a field-specific key, since not every list's items share
    one natural sort key (a `type_definitions` entry has `type`; a
    `directly_related_user_types` entry doesn't).
    """
    if isinstance(value, dict):
        return {key: _canonicalize_lists(sub_value) for key, sub_value in value.items()}

    if isinstance(value, list):
        canonical_items = [_canonicalize_lists(item) for item in value]
        return sorted(canonical_items, key=lambda item: json.dumps(item, sort_keys=True))

    return value


class ModelDiffer:
    """
    Compares OpenFGA models for equality.

    Uses normalized JSON comparison to avoid:
        - ordering issues
        - formatting differences
        - OpenFGA's server-added zero-value noise (see
          `_strip_server_defaults`)

    Only the fields that actually describe the schema (``schema_version``,
    ``type_definitions``) are compared. A model fetched back from OpenFGA
    (e.g. via ``get_latest_model()``) carries server-added metadata — most
    notably an ``id`` field, plus the zero-value noise described above —
    that a locally generated model never has; comparing the raw dicts
    wholesale would make every comparison against a real server response
    report "changed", even when the schema itself is logically identical.
    """

    #: Fields that define the schema itself. Anything else on a model dict
    #: (e.g. OpenFGA's server-assigned ``id``) is metadata, not schema, and
    #: must be ignored for equality purposes.
    SCHEMA_FIELDS = ("schema_version", "type_definitions")

    @classmethod
    def normalize(cls, model: dict[str, Any]) -> str:
        """
        Normalize a model to a stable JSON string containing only its
        schema-defining fields, with server-added zero-value noise
        stripped out.
        """
        schema_only = {field: model.get(field) for field in cls.SCHEMA_FIELDS}
        cleaned = _strip_server_defaults(schema_only)
        canonical = _canonicalize_lists(cleaned)
        return json.dumps(canonical, sort_keys=True)

    @classmethod
    def is_equal(
        cls,
        model_a: dict[str, Any],
        model_b: dict[str, Any],
    ) -> bool:
        return cls.normalize(model_a) == cls.normalize(model_b)

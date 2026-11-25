from py_authz.core.exceptions import ModelValidationError
from py_authz.validation.base import ModelValidator

_REWRITE_KEYS = (
    "this",
    "union",
    "computedUserset",
    "tupleToUserset",
    "intersection",
    "difference",
)


class DefaultModelValidator(ModelValidator):
    """
    Validation rules for OpenFGA models, run before upload so a bad model
    fails locally with a useful message instead of as a 400 from OpenFGA
    (which, inside `TenantManager.provision()`, means create store → fail
    → delete store on every attempt).

    Checks:
        - every type definition has a `type`, and no type is defined twice
        - every relation has a recognised rewrite
        - same-type references (`computedUserset`, `union`, ...) name a
          relation defined on the type, with no cycles
        - a `tupleToUserset`'s tupleset names a relation on the same type,
          and its computed relation exists on at least one type the
          tupleset can point at (when the model carries metadata)
        - every `directly_related_user_types` entry names a defined type,
          and a userset entry (`team#member`) names a relation that type
          defines
    """

    def validate(self, model: dict):
        if "type_definitions" not in model:
            raise ModelValidationError("Model missing type_definitions")

        type_relations: dict[str, dict] = {}
        for t in model["type_definitions"]:
            if "type" not in t:
                raise ModelValidationError("Type definition missing 'type'")
            if t["type"] in type_relations:
                raise ModelValidationError(f"Type {t['type']!r} is defined more than once")
            type_relations[t["type"]] = t.get("relations") or {}

        for t in model["type_definitions"]:
            relations = type_relations[t["type"]]

            for name, rel in relations.items():
                if not isinstance(rel, dict):
                    raise ModelValidationError(f"Invalid relation format: {name}")
                if not any(k in rel for k in _REWRITE_KEYS):
                    raise ModelValidationError(f"Relation '{name}' has no valid rewrite")

            detect_cycles(relations=relations)

            metadata = (t.get("metadata") or {}).get("relations") or {}
            self._check_subjects(t["type"], metadata, type_relations)
            for name, rel in relations.items():
                for ttu in _tuple_to_usersets(rel):
                    self._check_tuple_to_userset(t["type"], name, ttu, metadata, type_relations)

    @staticmethod
    def _check_subjects(type_name: str, metadata: dict, type_relations: dict[str, dict]) -> None:
        for rel_name, rel_meta in metadata.items():
            for subject in (rel_meta or {}).get("directly_related_user_types") or []:
                subject_type = subject.get("type")
                if subject_type not in type_relations:
                    raise ModelValidationError(
                        f"{type_name}#{rel_name} allows subject type {subject_type!r}, "
                        "which the model does not define"
                    )
                subject_relation = subject.get("relation")
                if subject_relation and subject_relation not in type_relations[subject_type]:
                    raise ModelValidationError(
                        f"{type_name}#{rel_name} allows subject "
                        f"'{subject_type}#{subject_relation}', but type {subject_type!r} "
                        f"has no relation {subject_relation!r}"
                    )

    @staticmethod
    def _check_tuple_to_userset(
        type_name: str,
        rel_name: str,
        ttu: dict,
        metadata: dict,
        type_relations: dict[str, dict],
    ) -> None:
        tupleset = (ttu.get("tupleset") or {}).get("relation")
        computed = (ttu.get("computedUserset") or {}).get("relation")
        if not tupleset or tupleset not in type_relations[type_name]:
            raise ModelValidationError(
                f"{type_name}#{rel_name} inherits through tupleset relation {tupleset!r}, "
                f"which type {type_name!r} does not define"
            )
        if tupleset not in metadata:
            return  # no metadata to say which types the tupleset points at
        parent_types = [
            s.get("type")
            for s in (metadata[tupleset] or {}).get("directly_related_user_types") or []
        ]
        if not any(computed in type_relations.get(p, {}) for p in parent_types):
            raise ModelValidationError(
                f"{type_name}#{rel_name} inherits {computed!r} through {tupleset!r}, "
                f"but none of {tupleset!r}'s subject types {parent_types} define {computed!r}"
            )


def _tuple_to_usersets(rewrite) -> list[dict]:
    """Every `tupleToUserset` node in one rewrite rule, at any depth."""
    if not isinstance(rewrite, dict):
        return []
    found: list[dict] = []
    if isinstance(rewrite.get("tupleToUserset"), dict):
        found.append(rewrite["tupleToUserset"])
    for combinator in ("union", "intersection"):
        for child in (rewrite.get(combinator) or {}).get("child", []):
            found.extend(_tuple_to_usersets(child))
    difference = rewrite.get("difference")
    if isinstance(difference, dict):
        found.extend(_tuple_to_usersets(difference.get("base")))
        found.extend(_tuple_to_usersets(difference.get("subtract")))
    return found


def _referenced_relations(rewrite) -> list:
    """
    Extract the same-type relation names a single OpenFGA rewrite rule
    directly depends on, recursing into `union`/`intersection`/
    `difference` combinators.

    `rewrite` is one relation's rewrite-rule dict — e.g. `{"this": {}}`,
    `{"computedUserset": {"relation": "owner"}}`, or
    `{"union": {"child": [...]}}` — exactly the shape
    `OpenFGAModelGenerator` emits and `DefaultModelValidator.validate`
    passes to `detect_cycles` for every relation on a type.

    `tupleToUserset`'s `computedUserset` is deliberately excluded: it names
    a relation on a *different* object (reached through the `tupleset`
    relation), not this type's own relation graph, so it can never
    participate in a same-type cycle.
    """
    if not isinstance(rewrite, dict):
        return []

    referenced: list = []

    computed = rewrite.get("computedUserset")
    if isinstance(computed, dict) and computed.get("relation"):
        referenced.append(computed["relation"])

    for combinator in ("union", "intersection"):
        child_rules = rewrite.get(combinator, {}).get("child", [])
        for child in child_rules:
            referenced.extend(_referenced_relations(child))

    difference = rewrite.get("difference")
    if isinstance(difference, dict):
        referenced.extend(_referenced_relations(difference.get("base", {})))
        referenced.extend(_referenced_relations(difference.get("subtract", {})))

    return referenced


def detect_cycles(relations: dict):
    """
    Raise if a type's relations reference each other in a cycle.

    `relations` maps relation name -> OpenFGA rewrite-rule dict (the shape
    `OpenFGAModelGenerator._generate_type` produces), not an adjacency list
    of relation names — each rewrite rule is walked via
    `_referenced_relations` to find the relation names it actually depends
    on, and that dependency graph is what gets checked for cycles.
    """
    visited = set()
    stack = set()

    def visit(node):
        if node not in relations:
            # A `union`/`inherits`/`computedUserset` reference (a same-
            # type name — see `_referenced_relations`'s docstring) that
            # doesn't name a relation actually defined on this type. Left
            # unchecked, `relations.get(node)` below returns `None`,
            # `_referenced_relations(None)` returns `[]`, and the walk
            # silently treats the typo as a dead end instead of failing
            # fast — the model then passes validation and fails only once
            # uploaded to a real OpenFGA server (see ARCH2-12).
            raise ModelValidationError(f"Relation references unknown relation '{node}'")
        if node in stack:
            raise ModelValidationError(f"Circular relation detected: {node}")
        if node in visited:
            return

        stack.add(node)
        visited.add(node)

        for child in _referenced_relations(relations.get(node)):
            visit(child)

        stack.remove(node)

    for r in relations:
        visit(r)

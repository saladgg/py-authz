from py_authz.validation.base import ModelValidator


class DefaultModelValidator(ModelValidator):
    """
    Basic validation rules for OpenFGA models.
    """

    def validate(self, model: dict):
        if "type_definitions" not in model:
            raise ValueError("Model missing type_definitions")

        for t in model["type_definitions"]:
            if "type" not in t:
                raise ValueError("Type definition missing 'type'")

            relations = t.get("relations", {})
            detect_cycles(relations=relations)

            for name, rel in relations.items():
                if not isinstance(rel, dict):
                    raise ValueError(f"Invalid relation format: {name}")

                # basic check
                if not any(
                    k in rel for k in ["this", "union", "computedUserset", "tupleToUserset"]
                ):
                    raise ValueError(f"Relation '{name}' has no valid rewrite")


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
        if node in stack:
            raise ValueError(f"Circular relation detected: {node}")
        if node in visited:
            return

        stack.add(node)
        visited.add(node)

        for child in _referenced_relations(relations.get(node)):
            visit(child)

        stack.remove(node)

    for r in relations:
        visit(r)

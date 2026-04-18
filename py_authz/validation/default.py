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
                if not any(k in rel for k in ["this", "union", "computedUserset"]):
                    raise ValueError(f"Relation '{name}' has no valid rewrite")


def detect_cycles(relations: dict):
    visited = set()
    stack = set()

    def visit(node):
        if node in stack:
            raise ValueError(f"Circular relation detected: {node}")
        if node in visited:
            return

        stack.add(node)
        visited.add(node)

        for child in relations.get(node, []):
            visit(child)

        stack.remove(node)

    for r in relations:
        visit(r)

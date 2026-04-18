from typing import Dict, Any, List, Type

from py_authz.modeling.base import ResourceModel, Relation
from py_authz.modeling.registry import registry


# -------------------------------------------------------------------
# Core Generator
# -------------------------------------------------------------------


class OpenFGAModelGenerator:
    """
    Generates OpenFGA authorization model JSON
    from registered ResourceModel classes.

    Supports:
        - direct relations
        - unions
        - computed usersets (inherits)
        - custom subject types
    """

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def generate(self) -> Dict[str, Any]:
        """
        Generate full OpenFGA model.

        Returns:
            dict: OpenFGA model JSON
        """
        return {
            "schema_version": "1.1",
            "type_definitions": self._generate_types(),
        }

    # -------------------------------------------------------------------
    # Type generation
    # -------------------------------------------------------------------

    def _generate_types(self) -> List[Dict[str, Any]]:
        types: List[Dict[str, Any]] = []

        # Always include base user type
        types.append({"type": "user"})

        for model in registry.all():
            types.append(self._generate_type(model))

        return types

    def _generate_type(self, model: Type[ResourceModel]) -> Dict[str, Any]:
        relation_map = self._relation_map(model)

        relations = {name: self._build_relation(rel) for name, rel in relation_map.items()}

        metadata = {
            "relations": {
                name: {
                    "directly_related_user_types": [
                        {"type": subject_type} for subject_type in rel.subjects
                    ]
                }
                for name, rel in relation_map.items()
            }
        }

        return {
            "type": model.type,
            "relations": relations,
            "metadata": metadata,
        }

    # -------------------------------------------------------------------
    # Relation helpers
    # -------------------------------------------------------------------

    def _relation_map(self, model: Type[ResourceModel]) -> Dict[str, Relation]:
        """
        Extract Relation objects from a ResourceModel.
        """
        mapping: Dict[str, Relation] = {}

        for attr in dir(model):
            value = getattr(model, attr)

            if isinstance(value, Relation):
                mapping[value.name] = value

        return mapping

    def _build_relation(self, rel: Relation) -> Dict[str, Any]:
        """
        Build OpenFGA relation definition.

        Handles:
            - direct relations (this)
            - unions
            - inherited/computed relations
        """
        parts: List[Dict[str, Any]] = []

        # -------------------------------------------------
        # Direct assignment (this)
        # -------------------------------------------------
        if rel.subjects:
            parts.append({"this": {}})

        # -------------------------------------------------
        # Union relations
        # -------------------------------------------------

        for name in rel.union:
            parts.append({"computedUserset": {"relation": name}})

        # -------------------------------------------------
        # Inherited relations
        # -------------------------------------------------
        for name in rel.inherits:
            parts.append(
                {
                    "computedUserset": {
                        "relation": name,
                    }
                }
            )

        # -------------------------------------------------
        # Final shape
        # -------------------------------------------------
        if not parts:
            return {}

        if len(parts) == 1:
            return parts[0]

        return {
            "union": {
                "child": parts,
            }
        }


# -------------------------------------------------------------------
# Convenience API
# -------------------------------------------------------------------


def generate_model() -> Dict[str, Any]:
    """
    Generate OpenFGA model from all registered ResourceModels.

    Returns:
        dict: OpenFGA model JSON
    """
    return OpenFGAModelGenerator().generate()

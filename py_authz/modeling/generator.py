from collections.abc import Iterable
from typing import Any

from py_authz.core.exceptions import ModelValidationError
from py_authz.modeling.base import Relation, ResourceModel, from_parent_pairs
from py_authz.modeling.registry import registry

# -------------------------------------------------------------------
# Subject parsing
# -------------------------------------------------------------------


def parse_subject(subject: str) -> dict[str, Any]:
    """
    Turn one `Relation(subjects=[...])` entry into an OpenFGA
    `directly_related_user_types` entry (ARCH3-6):

    - `"user"`          -> `{"type": "user"}`
    - `"user:*"`        -> `{"type": "user", "wildcard": {}}` (public access)
    - `"team#member"`   -> `{"type": "team", "relation": "member"}` (userset)

    It used to emit `{"type": "team#member"}` verbatim, which OpenFGA
    rejects.
    """
    if subject.endswith(":*"):
        subject_type = subject[:-2]
        if not subject_type or "#" in subject_type or ":" in subject_type:
            raise ModelValidationError(f"Invalid wildcard subject {subject!r}")
        return {"type": subject_type, "wildcard": {}}
    if "#" in subject:
        subject_type, _, relation = subject.partition("#")
        if not subject_type or not relation or "#" in relation or ":" in subject:
            raise ModelValidationError(f"Invalid userset subject {subject!r}")
        return {"type": subject_type, "relation": relation}
    if not subject or ":" in subject:
        raise ModelValidationError(f"Invalid subject type {subject!r}")
    return {"type": subject}


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
        - parent-relation inheritance (from_parent), single or multiple
          parent relations (tupleToUserset)
        - intersections (AND of named relations)
        - exclusions (base relation-def MINUS a named relation, i.e.
          OpenFGA's difference rewrite)
    """

    # -------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------

    def generate(self, *, models: Iterable[type[ResourceModel]] | None = None) -> dict[str, Any]:
        """
        Generate full OpenFGA model.

        Args:
            models: Explicit set of `ResourceModel` classes to generate
                types for, instead of everything registered in the global
                `py_authz.modeling.registry.registry` singleton. `None`
                (the default, and the only behavior before this argument
                existed) reads that global registry, same as always — an
                adopter's own models registered via `registry.register(...)`
                are unaffected either way. Pass an explicit iterable for a
                model that must never be mixed into (or read from) that
                shared registry, e.g. a second, independent model synced
                to its own OpenFGA store (see the control-plane API's
                dogfooded RBAC model, `control_plane/rbac_model.py`).

        Returns:
            dict: OpenFGA model JSON
        """
        return {
            "schema_version": "1.1",
            "type_definitions": self._generate_types(models),
        }

    # -------------------------------------------------------------------
    # Type generation
    # -------------------------------------------------------------------

    def _generate_types(
        self, models: Iterable[type[ResourceModel]] | None = None
    ) -> list[dict[str, Any]]:
        types: list[dict[str, Any]] = []
        seen: set[str] = set()

        for model in models if models is not None else registry.all():
            if model.type in seen:
                # OpenFGA rejects a model that defines a type twice (ARCH3-6).
                raise ModelValidationError(
                    f"Type {model.type!r} is defined by more than one ResourceModel"
                )
            seen.add(model.type)
            types.append(self._generate_type(model))

        # The base `user` type is implicit, unless a ResourceModel declares
        # it (e.g. to give users their own relations). Prepending it
        # unconditionally produced a duplicate `user` type (ARCH3-6).
        if "user" not in seen:
            types.insert(0, {"type": "user"})

        return types

    def _generate_type(self, model: type[ResourceModel]) -> dict[str, Any]:
        relation_map = self._relation_map(model)

        relations = {name: self._build_relation(rel) for name, rel in relation_map.items()}

        metadata = {
            "relations": {
                name: {
                    "directly_related_user_types": [
                        parse_subject(subject) for subject in rel.subjects
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

    def _relation_map(self, model: type[ResourceModel]) -> dict[str, Relation]:
        """
        Extract Relation objects from a ResourceModel.
        """
        mapping: dict[str, Relation] = {}

        for attr in dir(model):
            value = getattr(model, attr)

            if isinstance(value, Relation):
                mapping[value.name] = value

        return mapping

    def _build_relation(self, rel: Relation) -> dict[str, Any]:
        """
        Build OpenFGA relation definition.

        Handles:
            - direct relations (this)
            - unions
            - inherited/computed relations (alias of union)
            - parent-relation inheritance (tupleToUserset), one or many
              parent relations
            - intersections (AND of named relations)
            - exclusions (base relation-def MINUS a named relation)

        Every part below other than `exclude` becomes one child of an
        (implicit, single-child-collapsed) `union` — i.e. they're all
        ORed together, including `intersection` (which nests as just
        another child, matching OpenFGA's own grammar where
        `intersection` can appear as a child of `union`). `exclude` is
        different: OpenFGA's `difference` rewrite is a two-operand
        `base`/`subtract` pair, so it wraps the *entire* rewrite built
        from everything else rather than being one more child in the
        list — see `Relation.__init__`'s `exclude` docstring.
        """
        parts: list[dict[str, Any]] = []

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
        # Intersections (AND of named same-object relations)
        # -------------------------------------------------
        if rel.intersection:
            if len(rel.intersection) < 2:
                raise ModelValidationError(
                    f"Relation '{rel.name}' has intersection={rel.intersection!r} "
                    "with fewer than 2 relations — intersection (AND) requires "
                    "at least 2 relation names to combine"
                )
            parts.append(
                {
                    "intersection": {
                        "child": [
                            {"computedUserset": {"relation": name}} for name in rel.intersection
                        ]
                    }
                }
            )

        # -------------------------------------------------
        # Parent-relation inheritance (tupleToUserset), one child per pair
        # -------------------------------------------------
        for tupleset_relation, computed_relation in from_parent_pairs(rel.from_parent):
            parts.append(
                {
                    "tupleToUserset": {
                        "tupleset": {"relation": tupleset_relation},
                        "computedUserset": {"relation": computed_relation},
                    }
                }
            )

        # -------------------------------------------------
        # Exclusion (difference: base MINUS excluded relation)
        # -------------------------------------------------
        if rel.exclude:
            if rel.exclude == rel.name:
                raise ModelValidationError(f"Relation '{rel.name}' cannot exclude itself")
            if rel.exclude in (*rel.union, *rel.inherits, *rel.intersection):
                raise ModelValidationError(
                    f"Relation '{rel.name}' both includes and excludes "
                    f"'{rel.exclude}' — contradictory rewrite"
                )
            if not parts:
                raise ModelValidationError(
                    f"Relation '{rel.name}' has exclude={rel.exclude!r} but no "
                    "base relation-def (subjects/union/inherits/intersection/"
                    "from_parent) to subtract it from"
                )

            base = parts[0] if len(parts) == 1 else {"union": {"child": parts}}
            return {
                "difference": {
                    "base": base,
                    "subtract": {"computedUserset": {"relation": rel.exclude}},
                }
            }

        # -------------------------------------------------
        # Final shape
        # -------------------------------------------------
        if not parts:
            # Only reachable with an explicit `subjects=[]` and nothing
            # else — OpenFGA rejects an empty rewrite, so fail here with a
            # useful message instead of at upload time.
            raise ModelValidationError(
                f"Relation '{rel.name}' has no direct subjects and no "
                "union/inherits/intersection/from_parent — nothing can ever hold it"
            )

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


def generate_model(*, models: Iterable[type[ResourceModel]] | None = None) -> dict[str, Any]:
    """
    Generate OpenFGA model from all registered ResourceModels, or from an
    explicit `models` iterable — see `OpenFGAModelGenerator.generate()`.

    Returns:
        dict: OpenFGA model JSON
    """
    return OpenFGAModelGenerator().generate(models=models)

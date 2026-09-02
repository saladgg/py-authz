from py_authz.modeling.base import ResourceModel


class ResourceModelRegistry:
    """
    Registry for all resource models.

    Useful for:
        - validation
        - introspection
        - future model generation

    Named `ResourceModelRegistry` (not `ModelRegistry`) to avoid colliding
    with the unrelated `core.model_registry.ModelRegistry` Protocol (which
    tracks a tenant's active OpenFGA *model_id*, not registered
    `ResourceModel` classes) — the same naming-collision class ARCH-8
    already fixed once for `Authz.require`/`decorators.require` (see
    ARCH2-16).
    """

    def __init__(self):
        self._models: dict[str, type[ResourceModel]] = {}

    def register(self, model: type[ResourceModel]) -> None:
        if not model.type:
            raise ValueError(f"{model.__name__} must define a 'type'")

        self._models[model.type] = model

    def get(self, type_name: str) -> type[ResourceModel]:
        return self._models[type_name]

    def all(self):
        return self._models.values()


# Global registry (simple for now)
registry = ResourceModelRegistry()

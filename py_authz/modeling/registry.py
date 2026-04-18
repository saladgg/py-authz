from py_authz.modeling.base import ResourceModel


class ModelRegistry:
    """
    Registry for all resource models.

    Useful for:
        - validation
        - introspection
        - future model generation
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
registry = ModelRegistry()

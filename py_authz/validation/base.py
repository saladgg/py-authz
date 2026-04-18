from typing import Any, Protocol


class ModelValidator(Protocol):
    """
    Validates an authorization model before deployment.
    """

    def validate(self, model: dict[str, Any]) -> None: ...

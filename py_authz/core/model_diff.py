import json
from typing import Any


class ModelDiffer:
    """
    Compares OpenFGA models for equality.

    Uses normalized JSON comparison to avoid:
        - ordering issues
        - formatting differences
    """

    @staticmethod
    def normalize(model: dict[str, Any]) -> str:
        """
        Normalize model to stable JSON string.
        """
        return json.dumps(model, sort_keys=True)

    @classmethod
    def is_equal(
        cls,
        model_a: dict[str, Any],
        model_b: dict[str, Any],
    ) -> bool:
        return cls.normalize(model_a) == cls.normalize(model_b)

import json
from typing import Dict, Any


class ModelDiffer:
    """
    Compares OpenFGA models for equality.

    Uses normalized JSON comparison to avoid:
        - ordering issues
        - formatting differences
    """

    @staticmethod
    def normalize(model: Dict[str, Any]) -> str:
        """
        Normalize model to stable JSON string.
        """
        return json.dumps(model, sort_keys=True)

    @classmethod
    def is_equal(
        cls,
        model_a: Dict[str, Any],
        model_b: Dict[str, Any],
    ) -> bool:
        return cls.normalize(model_a) == cls.normalize(model_b)

import json
from typing import Optional

from py_authz.modeling.generator import generate_model


def generate_command(output: Optional[str] = None):
    """
    Generate OpenFGA model JSON.
    """
    model = generate_model()

    if output:
        with open(output, "w") as f:
            json.dump(model, f, indent=2)
        print(f"Model written to {output}")
    else:
        print(json.dumps(model, indent=2))

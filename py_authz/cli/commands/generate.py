import json

from py_authz.modeling.generator import generate_model
from py_authz.validation.default import DefaultModelValidator


def generate_command(output: str | None = None, *, validate: bool = True):
    """
    Generate OpenFGA model JSON.

    Validated by `DefaultModelValidator` by default — unlike `sync`
    (which always validates), `generate-model` used to skip validation
    entirely, letting a malformed model (including an undetectable
    circular relation — see ARCH-3) be "generated" and committed to
    version control or fed into CI without ever failing fast. Pass
    `validate=False` (`--no-validate` on the CLI) while iterating on an
    intentionally in-progress model.
    """
    model = generate_model()

    if validate:
        DefaultModelValidator().validate(model)

    if output:
        with open(output, "w") as f:
            json.dump(model, f, indent=2)
        print(f"Model written to {output}")
    else:
        print(json.dumps(model, indent=2))

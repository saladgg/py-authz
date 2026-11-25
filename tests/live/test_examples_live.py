"""
DX3-6: run `examples/seed.py` and then a subset of examples end to end
against the real OpenFGA, so they can't silently stop working.
"""

import os
import pathlib
import re
import subprocess  # noqa: S404 — runs this repo's own example scripts
import sys

import pytest

from .conftest import FGA_API_URL, requires_openfga

ROOT = pathlib.Path(__file__).resolve().parents[2]
RUN_AFTER_SEED = [
    "01_quickstart.py",
    "07_explain_and_bulk.py",
    "08_list_objects.py",
    "09_contextual_and_abac.py",
    "10_unit_testing.py",
    "11_hierarchical_permissions.py",
]


def _run(script: str, env: dict) -> str:
    result = subprocess.run(  # noqa: S603 — fixed interpreter and repo-local scripts
        [sys.executable, str(ROOT / "examples" / script)],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, f"{script} failed:\n{result.stdout}\n{result.stderr}"
    return result.stdout


@pytest.fixture(scope="module")
def seeded_env():
    env = {**os.environ, "FGA_API_URL": FGA_API_URL or "", "PYTHONPATH": str(ROOT)}
    out = _run("seed.py", env)
    for var in ("FGA_STORE_ID", "FGA_MODEL_ID"):
        match = re.search(rf"export {var}=(\S+)", out)
        assert match, f"seed.py printed no {var}:\n{out}"
        env[var] = match.group(1)
    return env


@requires_openfga
@pytest.mark.parametrize("script", RUN_AFTER_SEED)
def test_example_runs_against_real_openfga(script, seeded_env):
    _run(script, seeded_env)


@requires_openfga
def test_explain_example_prints_a_real_path(seeded_env):
    out = _run("07_explain_and_bulk.py", seeded_env)
    assert "via document:roadmap#viewer -> " in out
    assert out.rstrip().splitlines()  # produced output

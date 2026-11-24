"""Assert a built wheel advertises every user-facing install extra (ARCH3-1).

Until ARCH3-1 every extra lived under PEP 735 ``[dependency-groups]``,
which never reaches wheel metadata — so ``pip install "py-authz[fastapi]"``
silently installed only the core. This check fails the build if that
regresses, and also guards the other packaging promises (``py.typed``, the
bundled SQL migrations, no stray ``openfga-sdk`` runtime dependency).
"""

from __future__ import annotations

import sys
import tomllib
import zipfile
from email.parser import Parser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(dist_dir: str) -> int:
    wheels = sorted(Path(dist_dir).glob("py_authz-*.whl"))
    if not wheels:
        print(f"no py_authz wheel found in {dist_dir}", file=sys.stderr)
        return 1
    wheel = wheels[-1]

    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text())
    expected_extras = set(pyproject["project"]["optional-dependencies"])

    with zipfile.ZipFile(wheel) as zf:
        names = zf.namelist()
        metadata_name = next(n for n in names if n.endswith(".dist-info/METADATA"))
        metadata = Parser().parsestr(zf.read(metadata_name).decode())

    errors: list[str] = []

    provided = set(metadata.get_all("Provides-Extra") or [])
    missing = expected_extras - provided
    if missing:
        errors.append(f"extras missing from wheel metadata: {sorted(missing)}")

    requires = metadata.get_all("Requires-Dist") or []
    if any(r.lower().startswith("openfga-sdk") for r in requires):
        errors.append("openfga-sdk is a runtime dependency again (see ARCH3-14)")

    if "py_authz/py.typed" not in names:
        errors.append("py.typed missing from wheel (PEP 561, see DX2-3)")
    if not any(n.startswith("py_authz/storage/sql/") and n.endswith(".sql") for n in names):
        errors.append("bundled SQL migrations missing from wheel (see REL-4)")

    if errors:
        for e in errors:
            print(f"check-dist: {e}", file=sys.stderr)
        return 1

    print(f"check-dist: {wheel.name} OK — extras: {', '.join(sorted(provided))}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv) > 1 else "dist"))

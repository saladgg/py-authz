# Contributing to py-authz

Thanks for considering a contribution. This document covers local setup,
conventions, and how changes get released — the day-to-day content that
used to live in the README's "Development" section.

## Setup

```bash
make venv            # .venv with Python 3.13 (via uv)
make install-dev     # install all dependencies including dev tools
make format          # ruff format + ruff check --fix
make format-check    # ruff format --check
make lint            # ruff check + mypy
make check-dist      # build the wheel, assert extras / py.typed / SQL files ship
make test            # pytest with coverage
```

Pre-commit hooks run `ruff` (lint, with `--fix`), `ruff format`,
`end-of-file-fixer`, `trailing-whitespace`, and `gitleaks` (secret
scanning) on commit. Install them once with `uv run pre-commit install`.

## Conventions

- Async-only — every public method is a coroutine.
- Line length 100, ruff rules `E, F, I, UP, B, C4, SIM, S` (`S` = bandit-equivalent; `make lint` runs `ruff check` + mypy).
- All custom exceptions inherit from `AuthzError` in
  [`core/exceptions.py`](py_authz/core/exceptions.py).
- Optional dependencies are loaded on-demand via
  [`utils/deps.py`](py_authz/utils/deps.py) with helpful `ImportError`
  messages.
- Public code is fully type-hinted; `mypy py_authz` must pass clean
  (`make lint`).

## Testing

```bash
# Full suite + coverage (mocked/unit — no external services needed)
make test

# Single file
uv run pytest tests/core/test_enforcement.py

# Single test
uv run pytest tests/core/test_enforcement.py -k "test_name"

# Against a real OpenFGA + Keycloak + Redis + Postgres stack (docker compose)
make test-integration
```

`tests/conftest.py` provides a `MockOpenFGAClient`, pre-built
`Identity`/`Resource` fixtures, and an `AuthzEngine` wired to an
in-memory cache for fast unit tests. `tests/live/` exercises the same
code paths against real infrastructure and is skip-gated when that
infrastructure isn't reachable — see `make test-integration` above.

## Submitting a change

1. Fork the repo and branch off `main`.
2. Make your change, with tests — a change to `py_authz/` with no
   accompanying test is the most common reason a PR gets asked for a
   revision.
3. Run `make format`, `make lint`, and `make test` locally before
   opening the PR; CI runs the same checks (plus `tests/live/`) on every
   push and pull request.
4. Use [Conventional Commits](https://www.conventionalcommits.org) for
   your commit messages/PR title — `feat:`/`fix:`/`perf:`/`refactor:`
   etc. This isn't just style: merges to `main` are released
   automatically via
   [`python-semantic-release`](https://python-semantic-release.readthedocs.io),
   and the commit type determines the version bump (`feat` → minor,
   `fix`/`perf`/`refactor` → patch, `docs`/`chore`/`build`/`ci`/`test`/`style`
   → no release).

## Reporting a security issue

Please don't open a public issue for a suspected vulnerability — see
[`SECURITY.md`](SECURITY.md) for how to report one privately.

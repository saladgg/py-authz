"""
Shared fixtures for py_authz.control_plane route-level tests.

Existing test files (`test_auth.py`, `test_audit_routes.py`,
`test_operators_routes.py`) each define their own local fakes — kept
as-is rather than refactored onto this file, to avoid touching
already-passing tests. Everything added *after* those uses this
conftest instead of re-duplicating the same `FakeOIDCValidator`/
`FakeOperatorStore`/`FakeBootstrapper`/`rbac_authz` boilerplate per file.
"""

import pytest

from py_authz.api import Authz
from py_authz.control_plane.rbac_model import RBAC_MODELS
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.exceptions import AuthenticationError
from py_authz.core.types import Identity
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.testkit import InMemoryFGAClient


class FakeOIDCValidator:
    def __init__(self, tokens: dict[str, dict] | None = None):
        self.tokens = tokens or {"good-token": {"sub": "alice", "email": "alice@example.com"}}

    async def validate(self, token: str) -> dict:
        if token not in self.tokens:
            raise AuthenticationError("invalid token")
        return self.tokens[token]

    def to_identity(self, payload: dict) -> Identity:
        return Identity(id=f"user:{payload['sub']}", attributes=payload)


class FakeOperatorStore:
    def __init__(self):
        self.logins: list[str] = []

    async def record_login(self, *, subject, email):
        self.logins.append(subject)


class FakeBootstrapper:
    def __init__(self):
        self.calls: list[Identity] = []

    async def maybe_bootstrap(self, identity: Identity) -> None:
        self.calls.append(identity)


@pytest.fixture
def rbac_authz():
    reg = ResourceModelRegistry()
    # Strict mode + the full RBAC model (incl. the `service_account`
    # subject type): reject what a real OpenFGA rejects (ARCH3-9).
    for model in RBAC_MODELS:
        reg.register(model)
    client = InMemoryFGAClient(model_registry=reg, strict=True)
    return Authz(AuthzEngine(fga_client=client))


@pytest.fixture
def oidc_validator():
    return FakeOIDCValidator()


@pytest.fixture
def operator_store():
    return FakeOperatorStore()


@pytest.fixture
def bootstrapper():
    return FakeBootstrapper()


def bearer(token: str = "good-token") -> dict[str, str]:  # noqa: S107 — fixture default
    return {"Authorization": f"Bearer {token}"}


ALICE = Identity(id="user:alice")

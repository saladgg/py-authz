"""Tests for py_authz.sync.SyncAuthz — the blocking facade over `Authz`."""

import asyncio
import threading

import pytest

from py_authz.core.exceptions import AuthorizationDenied
from py_authz.core.types import Identity
from py_authz.modeling.base import Relation, ResourceModel
from py_authz.modeling.registry import ResourceModelRegistry
from py_authz.sync import SyncAuthz
from py_authz.testkit import make_fake_authz


class Document(ResourceModel):
    type = "document"
    owner = Relation("owner")
    viewer = Relation("viewer", union=["owner"])


@pytest.fixture
def fake_authz():
    reg = ResourceModelRegistry()
    reg.register(Document)
    return make_fake_authz(model_registry=reg)


@pytest.fixture
def sync_authz(fake_authz):
    with SyncAuthz(fake_authz) as sync:
        yield sync


def test_exposes_the_wrapped_authz(fake_authz, sync_authz):
    assert sync_authz.authz is fake_authz


def test_require_raises_in_the_calling_thread_when_denied(sync_authz):
    alice = Identity(id="user:alice")
    sync_authz.grant(alice, "owner", Document(id="d1"))

    sync_authz.require("viewer", alice, Document(id="d1"))  # allowed: no exception
    with pytest.raises(AuthorizationDenied):
        sync_authz.require("viewer", alice, Document(id="d2"))


def test_other_coroutine_methods_are_exposed_as_blocking_calls(fake_authz, sync_authz):
    alice = Identity(id="user:alice")

    sync_authz.grant(alice, "owner", Document(id="d1"))
    sync_authz.grant(alice, "owner", Document(id="d2"))
    sync_authz.revoke(alice, "owner", Document(id="d2"))

    assert sync_authz.list_objects("viewer", alice, "document") == ["document:d1"]
    blocking = sync_authz.list_objects
    assert blocking.__name__ == "list_objects"
    assert blocking.__doc__ == fake_authz.list_objects.__doc__


def test_non_coroutine_attributes_pass_through_unchanged(fake_authz, sync_authz):
    assert sync_authz._engine is fake_authz._engine
    with pytest.raises(AttributeError):
        sync_authz.no_such_method  # noqa: B018


def test_calling_from_its_own_loop_thread_raises_instead_of_deadlocking(sync_authz):
    alice = Identity(id="user:alice")

    async def nested():
        # Runs on SyncAuthz's own loop thread; a blocking call here would
        # wait on the very loop it is blocking.
        return sync_authz.can("viewer", alice, Document(id="d1"))

    with pytest.raises(RuntimeError, match="deadlock"):
        sync_authz.run(nested())


def test_a_call_exceeding_the_timeout_raises_and_is_cancelled(fake_authz):
    cancelled = threading.Event()

    async def slow():
        try:
            await asyncio.sleep(10)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    with SyncAuthz(fake_authz, timeout=0.05) as sync:
        with pytest.raises(TimeoutError):
            sync.run(slow())

        assert cancelled.wait(timeout=2), "the timed-out call must be cancelled on the loop"


def test_close_leaves_a_still_running_loop_open(fake_authz, monkeypatch):
    """If the loop thread hasn't stopped within `close()`'s join timeout
    (e.g. a wedged callback), `close()` must not call `loop.close()` on a
    running loop — that raises `RuntimeError`."""
    sync = SyncAuthz(fake_authz)
    release = threading.Event()
    wedged = threading.Event()

    def wedge():
        wedged.set()
        release.wait(timeout=5)

    async def aclose_then_wedge(**_kwargs):
        # Queue `wedge` one hop later than the callback that hands
        # `aclose()`'s result back to close(), so it is queued after that
        # but ahead of close()'s `loop.stop`: the loop is still busy in
        # `wedge` when close() checks whether it stopped.
        loop = asyncio.get_running_loop()
        loop.call_soon(loop.call_soon, wedge)

    monkeypatch.setattr(fake_authz, "aclose", aclose_then_wedge)
    real_join = sync._thread.join
    monkeypatch.setattr(sync._thread, "join", lambda timeout=None: wedged.wait(timeout=5))

    sync.close()  # must not raise

    assert sync._loop.is_closed() is False
    release.set()
    real_join(timeout=5)
    assert not sync._thread.is_alive()
    sync._loop.close()

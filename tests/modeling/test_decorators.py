import pytest


def test_sync_decorator_allows():
    from py_authz.core.types import Identity
    from py_authz.modeling import Relation, ResourceModel
    from py_authz.modeling.decorators import authorize

    class Doc(ResourceModel):
        type = "document"
        view = Relation("viewer")

    class MockAuthz:
        async def can(self, *args, **kwargs):
            return True

    authz = MockAuthz()

    @authorize(
        authz,
        Doc.view,
        user_getter=lambda u, d: u,
        resource_getter=lambda u, d: d,
    )
    def handler(user, doc):
        return "ok"

    result = handler(Identity(id="user:1"), Doc("1"))

    assert result == "ok"


# ---------------------------------------------------------------------------
# ARCH3-2: the sync decorator against a REAL OpenFGAClient over a socket.
# Every other test here uses a MockAuthz with no HTTP client at all, which
# is why the original bug — a fresh event loop per call breaking the
# client's loop-bound connection pool on every other call — went unseen.
# ---------------------------------------------------------------------------


@pytest.fixture
def openfga_stub():
    """A minimal HTTP server answering every OpenFGA `check` with allowed."""
    import json
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"  # keep-alive, so connections get pooled

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.dumps({"allowed": True}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_address[1]}"
    server.shutdown()


def _real_authz(api_url):
    from py_authz.api import Authz
    from py_authz.clients.openfga import OpenFGAClient
    from py_authz.core.enforcement import AuthzEngine

    client = OpenFGAClient(api_url=api_url, store_id="store", model_id=None, max_retries=0)
    return Authz(AuthzEngine(fga_client=client))


def test_sync_decorator_works_on_every_call_with_a_real_client(openfga_stub):
    from py_authz.core.types import Identity
    from py_authz.modeling import Relation, ResourceModel
    from py_authz.modeling.decorators import authorize

    class Doc(ResourceModel):
        type = "document"
        view = Relation("viewer")

    authz = _real_authz(openfga_stub)

    @authorize(authz, Doc.view, user_getter=lambda u, d: u, resource_getter=lambda u, d: d)
    def handler(user, doc):
        return "ok"

    results = [handler(Identity(id="user:1"), Doc("1")) for _ in range(5)]

    assert results == ["ok"] * 5


def test_sync_authz_serves_concurrent_threads_on_one_loop(openfga_stub):
    from concurrent.futures import ThreadPoolExecutor

    from py_authz.core.types import Identity, Resource
    from py_authz.sync import SyncAuthz

    with (
        SyncAuthz(_real_authz(openfga_stub)) as sync_authz,
        ThreadPoolExecutor(max_workers=8) as pool,
    ):
        results = list(
            pool.map(
                lambda i: sync_authz.can(
                    "viewer", Identity(id=f"user:{i}"), Resource(type="doc", id="1")
                ),
                range(40),
            )
        )

    assert results == [True] * 40


def test_sync_authz_refuses_calls_after_close(openfga_stub):
    from py_authz.core.types import Identity, Resource
    from py_authz.sync import SyncAuthz

    sync_authz = SyncAuthz(_real_authz(openfga_stub))
    sync_authz.close()
    sync_authz.close()  # idempotent

    with pytest.raises(RuntimeError, match="closed"):
        sync_authz.can("viewer", Identity(id="user:1"), Resource(type="doc", id="1"))

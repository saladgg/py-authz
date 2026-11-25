"""ARCH3-8 — `OpenFGAClient.expand()`/`explain()` and the path walk."""

import pytest

from py_authz.clients.expand_path import find_path
from py_authz.clients.openfga import OpenFGAClient
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource


def _users(*users):
    return {"leaf": {"users": {"users": list(users)}}}


def _computed(userset):
    return {"leaf": {"computed": {"userset": userset}}}


def _ttu(*usersets):
    return {
        "leaf": {
            "tupleToUserset": {
                "tupleset": "x",
                "computed": [{"userset": u} for u in usersets],
            }
        }
    }


def _union(*nodes):
    return {"union": {"nodes": list(nodes)}}


def fake_expand(trees):
    calls = []

    async def expand(relation, obj):
        calls.append(f"{obj}#{relation}")
        return trees.get(f"{obj}#{relation}")

    expand.calls = calls
    return expand


@pytest.mark.asyncio
async def test_direct_user():
    expand = fake_expand({"doc:1#viewer": _users("user:alice")})
    assert await find_path(expand, "user:alice", "viewer", "doc:1") == [
        "doc:1#viewer",
        "user:alice",
    ]


@pytest.mark.asyncio
async def test_computed_then_parent_then_userset():
    expand = fake_expand(
        {
            "doc:1#viewer": _union(_users("user:bob"), _computed("doc:1#editor")),
            "doc:1#editor": _ttu("folder:eng#editor"),
            "folder:eng#editor": _users("team:core#member"),
            "team:core#member": _users("user:alice"),
        }
    )
    assert await find_path(expand, "user:alice", "viewer", "doc:1") == [
        "doc:1#viewer",
        "doc:1#editor",
        "folder:eng#editor",
        "team:core#member",
        "user:alice",
    ]


@pytest.mark.asyncio
async def test_wildcard_matches_same_type_only():
    expand = fake_expand({"doc:1#viewer": _users("user:*")})
    assert await find_path(expand, "user:alice", "viewer", "doc:1") == ["doc:1#viewer", "user:*"]
    assert await find_path(expand, "service:ci", "viewer", "doc:1") is None


@pytest.mark.asyncio
async def test_intersection_needs_every_branch_and_difference_uses_base():
    trees = {
        "doc:1#access": {
            "difference": {
                "base": {
                    "intersection": {
                        "nodes": [_computed("doc:1#editor"), _computed("doc:1#verified")]
                    }
                },
                "subtract": _computed("doc:1#banned"),
            }
        },
        "doc:1#editor": _users("user:alice"),
        "doc:1#verified": _users("user:alice", "user:bob"),
    }
    expand = fake_expand(trees)
    assert await find_path(expand, "user:alice", "access", "doc:1") == [
        "doc:1#access",
        "doc:1#editor",
        "user:alice",
    ]
    assert await find_path(expand, "user:bob", "access", "doc:1") is None


@pytest.mark.asyncio
async def test_cycles_and_budget_are_bounded():
    expand = fake_expand(
        {
            "g:a#member": _users("g:b#member"),
            "g:b#member": _users("g:a#member"),
        }
    )
    assert await find_path(expand, "user:alice", "member", "g:a") is None
    assert len(expand.calls) == 2

    chain = {f"g:{i}#member": _users(f"g:{i + 1}#member") for i in range(100)}
    expand = fake_expand(chain)
    assert await find_path(expand, "user:alice", "member", "g:0", max_calls=5) is None
    assert len(expand.calls) == 5


@pytest.mark.asyncio
async def test_unknown_node_shapes_and_empty_trees_find_nothing():
    expand = fake_expand(
        {
            "doc:1#viewer": _union({"weird": {}}, {"leaf": {"other": {}}}, _computed("")),
        }
    )
    assert await find_path(expand, "user:alice", "viewer", "doc:1") is None
    assert await find_path(fake_expand({}), "user:alice", "viewer", "doc:1") is None


class _ExpandHTTP:
    """Serves canned `/expand` trees keyed by `object#relation`."""

    def __init__(self, trees, allowed=True):
        self.trees = trees
        self.allowed = allowed
        self.payloads: list[dict] = []

    async def request(self, method, path, json=None, **_kwargs):
        self.payloads.append(json)
        if path.endswith("/check"):
            data = {"allowed": self.allowed}
        else:
            key = f"{json['tuple_key']['object']}#{json['tuple_key']['relation']}"
            node = self.trees.get(key)
            data = {"tree": {"root": node}} if node else {}

        class _R:
            status_code = 200

            def raise_for_status(self):
                pass

            def json(self):
                return data

        return _R()

    async def aclose(self):
        pass


@pytest.mark.asyncio
async def test_openfga_client_explain_returns_path_and_engine_surfaces_it():
    http = _ExpandHTTP(
        {
            "document:roadmap#viewer": _computed("document:roadmap#owner"),
            "document:roadmap#owner": _users("user:alice"),
        }
    )
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id="m1", http_client=http)
    engine = AuthzEngine(fga_client=client, cache=None)

    result = await engine.explain(
        AuthzRequest(
            identity=Identity(id="user:alice"),
            action="viewer",
            resource=Resource(type="document", id="roadmap"),
        )
    )

    assert result.allowed is True
    assert result.path == ["document:roadmap#viewer", "document:roadmap#owner", "user:alice"]
    expand_payload = http.payloads[1]
    assert expand_payload["tuple_key"] == {"relation": "viewer", "object": "document:roadmap"}
    assert expand_payload["authorization_model_id"] == "m1"


@pytest.mark.asyncio
async def test_openfga_client_explain_forwards_contextual_tuples_and_returns_none_without_path():
    http = _ExpandHTTP({})
    client = OpenFGAClient(api_url="http://fake", store_id="s1", model_id=None, http_client=http)
    ctx = [{"user": "user:alice", "relation": "viewer", "object": "document:x"}]

    assert await client.explain("user:alice", "viewer", "document:x", contextual_tuples=ctx) is None
    assert http.payloads[0]["contextual_tuples"] == {"tuple_keys": ctx}
    assert await client.expand("viewer", "document:x") == {}

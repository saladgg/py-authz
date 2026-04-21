import pytest

from py_authz.core.types import Identity, Resource


@pytest.mark.asyncio
async def test_grant_writes_single_tuple(authz, mock_fga_client, identity, resource):
    await authz.grant(identity, "viewer", resource)

    assert mock_fga_client.writes == [
        {
            "user": identity.id,
            "relation": "viewer",
            "object": resource.to_fga_object(),
        }
    ]
    # grant should not issue any deletes
    assert mock_fga_client.deletes == []


@pytest.mark.asyncio
async def test_grant_passes_no_deletes_argument(authz, mock_fga_client, identity, resource):
    await authz.grant(identity, "editor", resource)

    writes, deletes = mock_fga_client.write_tuples_calls[0]
    assert len(writes) == 1
    # Authz.grant calls write_tuples with writes= only — deletes should be None
    assert deletes is None


@pytest.mark.asyncio
async def test_revoke_deletes_single_tuple(authz, mock_fga_client, identity, resource):
    await authz.revoke(identity, "viewer", resource)

    assert mock_fga_client.deletes == [
        {
            "user": identity.id,
            "relation": "viewer",
            "object": resource.to_fga_object(),
        }
    ]
    # revoke should send an empty writes list (not None)
    writes, deletes = mock_fga_client.write_tuples_calls[0]
    assert writes == []
    assert len(deletes) == 1


@pytest.mark.asyncio
async def test_grant_many_writes_all_tuples(authz, mock_fga_client):
    users = [Identity(id=f"user:{i}") for i in range(3)]
    res = Resource(type="document", id="42")

    await authz.grant_many([(u, "viewer", res) for u in users])

    assert len(mock_fga_client.writes) == 3
    assert {w["user"] for w in mock_fga_client.writes} == {u.id for u in users}
    assert all(w["relation"] == "viewer" for w in mock_fga_client.writes)
    assert all(w["object"] == "document:42" for w in mock_fga_client.writes)


@pytest.mark.asyncio
async def test_grant_many_with_empty_list_still_calls_client(authz, mock_fga_client):
    await authz.grant_many([])

    # one call should be made with an empty writes list
    assert len(mock_fga_client.write_tuples_calls) == 1
    writes, deletes = mock_fga_client.write_tuples_calls[0]
    assert writes == []
    assert deletes is None


@pytest.mark.asyncio
async def test_revoke_many_deletes_all_tuples(authz, mock_fga_client):
    users = [Identity(id=f"user:{i}") for i in range(2)]
    res = Resource(type="document", id="99")

    await authz.revoke_many([(u, "editor", res) for u in users])

    assert len(mock_fga_client.deletes) == 2
    writes, deletes = mock_fga_client.write_tuples_calls[0]
    assert writes == []
    assert len(deletes) == 2
    assert all(d["relation"] == "editor" for d in deletes)


@pytest.mark.asyncio
async def test_revoke_many_with_empty_list(authz, mock_fga_client):
    await authz.revoke_many([])

    writes, deletes = mock_fga_client.write_tuples_calls[0]
    assert writes == []
    # Empty list is falsy; implementation passes deletes=[] which becomes None in the mock
    assert deletes is None or deletes == []


@pytest.mark.asyncio
async def test_grant_uses_resource_to_fga_object(authz, mock_fga_client, identity):
    res = Resource(type="project", id="alpha")

    await authz.grant(identity, "owner", res)

    assert mock_fga_client.writes[0]["object"] == "project:alpha"

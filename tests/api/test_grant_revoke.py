import pytest

from py_authz.api import Authz
from py_authz.core.enforcement import AuthzEngine
from py_authz.core.types import AuthzRequest, Identity, Resource
from py_authz.modeling.base import ResourceModel
from tests.conftest import RecordingAuditLogger


class GrantRevokeDoc(ResourceModel):
    type = "document"


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


# ----------------------------------------------------------------------
# Regression coverage: `grant`/`revoke`/`grant_many`/`revoke_many` must
# also accept a `ResourceModel` instance directly, not just a raw
# `Resource` — the README and `examples/06_multitenant.py` both document
# and use exactly that (`await authz.grant(alice, "owner", report)` where
# `report = Document(id="report")`), but `ResourceModel` has no
# `to_fga_object()` of its own (only `Resource` does), so this used to
# raise `AttributeError` for the documented usage.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_accepts_a_resource_model_instance(authz, mock_fga_client, identity):
    doc = GrantRevokeDoc(id="roadmap")

    await authz.grant(identity, "owner", doc)

    assert mock_fga_client.writes[0]["object"] == "document:roadmap"


@pytest.mark.asyncio
async def test_revoke_accepts_a_resource_model_instance(authz, mock_fga_client, identity):
    doc = GrantRevokeDoc(id="roadmap")

    await authz.revoke(identity, "owner", doc)

    assert mock_fga_client.deletes[0]["object"] == "document:roadmap"


@pytest.mark.asyncio
async def test_grant_many_accepts_resource_model_instances(authz, mock_fga_client, identity):
    doc = GrantRevokeDoc(id="roadmap")

    await authz.grant_many([(identity, "viewer", doc)])

    assert mock_fga_client.writes[0]["object"] == "document:roadmap"


@pytest.mark.asyncio
async def test_revoke_many_accepts_resource_model_instances(authz, mock_fga_client, identity):
    doc = GrantRevokeDoc(id="roadmap")

    await authz.revoke_many([(identity, "viewer", doc)])

    assert mock_fga_client.deletes[0]["object"] == "document:roadmap"


# ----------------------------------------------------------------------
# Regression coverage for DX-2: grant/revoke must invalidate the cache
# entry for the exact relation being granted/revoked, so an immediately-
# following check doesn't return a stale cached result.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_invalidates_cached_denied_result(authz, identity, resource, cache):
    request = AuthzRequest(identity=identity, action="viewer", resource=resource)
    await cache.set(request.cache_key(), False)  # prime a stale "denied"

    await authz.grant(identity, "viewer", resource)

    assert await cache.get(request.cache_key()) is None


@pytest.mark.asyncio
async def test_revoke_invalidates_cached_allowed_result(authz, identity, resource, cache):
    request = AuthzRequest(identity=identity, action="viewer", resource=resource)
    await cache.set(request.cache_key(), True)  # prime a stale "allowed"

    await authz.revoke(identity, "viewer", resource)

    assert await cache.get(request.cache_key()) is None


@pytest.mark.asyncio
async def test_grant_invalidation_uses_resource_model_type_and_id(authz, identity, cache):
    """The cache key must be computed from the resource's actual type/id
    even when a ResourceModel (not a raw Resource) is passed."""
    doc = GrantRevokeDoc(id="roadmap")
    request = AuthzRequest(identity=identity, action="owner", resource=doc.to_resource())
    await cache.set(request.cache_key(), False)

    await authz.grant(identity, "owner", doc)

    assert await cache.get(request.cache_key()) is None


@pytest.mark.asyncio
async def test_grant_many_invalidates_each_entry(authz, cache):
    users = [Identity(id=f"user:{i}") for i in range(2)]
    res = Resource(type="document", id="42")
    requests = [AuthzRequest(identity=u, action="viewer", resource=res) for u in users]

    for req in requests:
        await cache.set(req.cache_key(), False)

    await authz.grant_many([(u, "viewer", res) for u in users])

    for req in requests:
        assert await cache.get(req.cache_key()) is None


@pytest.mark.asyncio
async def test_revoke_many_invalidates_each_entry(authz, cache):
    users = [Identity(id=f"user:{i}") for i in range(2)]
    res = Resource(type="document", id="99")
    requests = [AuthzRequest(identity=u, action="editor", resource=res) for u in users]

    for req in requests:
        await cache.set(req.cache_key(), True)

    await authz.revoke_many([(u, "editor", res) for u in users])

    for req in requests:
        assert await cache.get(req.cache_key()) is None


@pytest.mark.asyncio
async def test_grant_does_not_invalidate_other_relations(authz, identity, resource, cache):
    """
    Documented scope: only the exact granted relation's cache entry is
    invalidated — a different (implied) relation on the same resource is
    untouched.
    """
    editor_request = AuthzRequest(identity=identity, action="editor", resource=resource)
    await cache.set(editor_request.cache_key(), False)

    await authz.grant(identity, "owner", resource)  # a different relation

    assert await cache.get(editor_request.cache_key()) is False


@pytest.mark.asyncio
async def test_grant_without_cache_configured_does_not_raise(mock_fga_client, identity, resource):
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None)
    authz = Authz(engine)

    # Should not raise even though there's no cache to invalidate.
    await authz.grant(identity, "viewer", resource)
    await authz.revoke(identity, "viewer", resource)


# ----------------------------------------------------------------------
# Regression coverage for ARCH2-2: grant/revoke (and their *_many
# variants) bypass `enforce()` entirely, so they previously never
# produced an audit event or a metrics counter — the highest-value
# events for a compliance trail (who granted/revoked what) were silently
# unrecorded.
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_records_audit_event_and_metrics(mock_fga_client, identity, resource):
    from py_authz.core.metrics import Metrics

    audit = RecordingAuditLogger()
    metrics = Metrics()
    engine = AuthzEngine(
        fga_client=mock_fga_client, cache=None, audit_logger=audit, metrics=metrics
    )
    authz = Authz(engine)

    await authz.grant(identity, "viewer", resource)
    await engine.flush_audit_logs()

    assert len(audit.events) == 1
    event = audit.events[0]
    assert event.allowed is True
    assert event.user_id == identity.id
    assert event.action == "viewer"
    assert event.resource == resource.to_fga_object()
    assert event.reason_data == {"operation": "grant", "relation": "viewer"}
    assert metrics.counters.get("authz_grant_total") == 1


@pytest.mark.asyncio
async def test_revoke_records_audit_event_and_metrics(mock_fga_client, identity, resource):
    from py_authz.core.metrics import Metrics

    audit = RecordingAuditLogger()
    metrics = Metrics()
    engine = AuthzEngine(
        fga_client=mock_fga_client, cache=None, audit_logger=audit, metrics=metrics
    )
    authz = Authz(engine)

    await authz.revoke(identity, "viewer", resource)
    await engine.flush_audit_logs()

    assert len(audit.events) == 1
    assert audit.events[0].reason_data == {"operation": "revoke", "relation": "viewer"}
    assert metrics.counters.get("authz_revoke_total") == 1


@pytest.mark.asyncio
async def test_grant_many_records_one_audit_event_per_tuple(mock_fga_client, identity):
    from py_authz.core.metrics import Metrics

    audit = RecordingAuditLogger()
    metrics = Metrics()
    engine = AuthzEngine(
        fga_client=mock_fga_client, cache=None, audit_logger=audit, metrics=metrics
    )
    authz = Authz(engine)

    users = [Identity(id=f"user:{i}") for i in range(3)]
    res = Resource(type="document", id="42")

    await authz.grant_many([(u, "viewer", res) for u in users])
    await engine.flush_audit_logs()

    assert len(audit.events) == 3
    assert metrics.counters.get("authz_grant_total") == 3


@pytest.mark.asyncio
async def test_revoke_many_records_one_audit_event_per_tuple(mock_fga_client, identity):
    from py_authz.core.metrics import Metrics

    audit = RecordingAuditLogger()
    metrics = Metrics()
    engine = AuthzEngine(
        fga_client=mock_fga_client, cache=None, audit_logger=audit, metrics=metrics
    )
    authz = Authz(engine)

    users = [Identity(id=f"user:{i}") for i in range(2)]
    res = Resource(type="document", id="99")

    await authz.revoke_many([(u, "editor", res) for u in users])
    await engine.flush_audit_logs()

    assert len(audit.events) == 2
    assert metrics.counters.get("authz_revoke_total") == 2


@pytest.mark.asyncio
async def test_grant_without_audit_logger_or_metrics_does_not_raise(
    mock_fga_client, identity, resource
):
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None)
    authz = Authz(engine)

    # Neither audit_logger nor metrics configured — record_write() must
    # be a safe no-op, not raise.
    await authz.grant(identity, "viewer", resource)


# -------------------------------------------------------------------
# `reason`/`actor` (CP-8: a control-plane API's mandatory manual
# grant/revoke justification, and attributing the operator that
# performed a grant on someone else's behalf).
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_grant_reason_lands_in_audit_event(mock_fga_client, identity, resource):
    audit = RecordingAuditLogger()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None, audit_logger=audit)
    authz = Authz(engine)

    await authz.grant(identity, "viewer", resource, reason="onboarding ticket #123")
    await engine.flush_audit_logs()

    event = audit.events[0]
    assert event.reason == "onboarding ticket #123"
    assert event.reason_data["reason"] == "onboarding ticket #123"


@pytest.mark.asyncio
async def test_grant_actor_recorded_without_changing_subject(mock_fga_client, identity, resource):
    audit = RecordingAuditLogger()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None, audit_logger=audit)
    authz = Authz(engine)
    operator = Identity(id="user:operator-1")

    await authz.grant(identity, "viewer", resource, reason="manual grant", actor=operator)
    await engine.flush_audit_logs()

    event = audit.events[0]
    # The tuple's subject stays `identity` — the operator performing the
    # grant is recorded in `reason_data`, not swapped in as `user_id`.
    assert event.user_id == identity.id
    assert event.reason_data["actor"] == operator.id


@pytest.mark.asyncio
async def test_revoke_reason_and_actor_recorded(mock_fga_client, identity, resource):
    audit = RecordingAuditLogger()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None, audit_logger=audit)
    authz = Authz(engine)
    operator = Identity(id="user:operator-2")

    await authz.revoke(identity, "viewer", resource, reason="offboarding", actor=operator)
    await engine.flush_audit_logs()

    event = audit.events[0]
    assert event.reason == "offboarding"
    assert event.reason_data["actor"] == operator.id


@pytest.mark.asyncio
async def test_grant_without_reason_keeps_default_reason_string(
    mock_fga_client, identity, resource
):
    audit = RecordingAuditLogger()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None, audit_logger=audit)
    authz = Authz(engine)

    await authz.grant(identity, "viewer", resource)
    await engine.flush_audit_logs()

    event = audit.events[0]
    assert event.reason == "grant via Authz.grant"
    assert "reason" not in event.reason_data
    assert "actor" not in event.reason_data


@pytest.mark.asyncio
@pytest.mark.parametrize("operation", ["grant", "revoke"])
async def test_bulk_operations_record_reason_and_actor(mock_fga_client, operation):
    """ARCH3-17: `grant_many`/`revoke_many` used to drop the CP-18 audit
    context that `grant`/`revoke` record."""
    audit = RecordingAuditLogger()
    engine = AuthzEngine(fga_client=mock_fga_client, cache=None, audit_logger=audit)
    authz = Authz(engine)
    operator = Identity(id="user:operator-3")
    tuples = [
        (Identity(id="user:a"), "viewer", Resource(type="document", id="1")),
        (Identity(id="user:b"), "viewer", Resource(type="document", id="1")),
    ]

    await getattr(authz, f"{operation}_many")(tuples, reason="bulk import", actor=operator)
    await engine.flush_audit_logs()

    assert len(audit.events) == 2
    for event in audit.events:
        assert event.reason == "bulk import"
        assert event.reason_data["actor"] == operator.id
        assert event.reason_data["operation"] == operation

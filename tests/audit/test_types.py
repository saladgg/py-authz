from datetime import datetime

from py_authz.audit.types import AuditEvent


def test_audit_event_required_fields_and_defaults():
    ts = datetime(2026, 4, 18)
    event = AuditEvent(
        timestamp=ts,
        tenant_id=None,
        user_id="user:1",
        action="view",
        resource="doc:1",
        allowed=False,
    )

    assert event.tenant_id is None
    assert event.reason is None
    assert event.reason_data is None
    assert event.request_id is None
    assert event.allowed is False

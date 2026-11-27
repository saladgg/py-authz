from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class AuditEvent:
    """
    Represents a single audit log event.

    `tenant_id` is the tenant the deciding engine serves (set by
    `MultiTenantAuthz`; `None` for a standalone engine). `store_id` is the
    OpenFGA store the decision ran against. Before ARCH3-16, `tenant_id`
    held the store id and there was no `store_id`.
    """

    timestamp: datetime
    tenant_id: str | None
    user_id: str
    action: str
    resource: str
    allowed: bool
    request_id: str | None = None

    reason: str | None = None
    reason_data: Any | None = None
    store_id: str | None = None

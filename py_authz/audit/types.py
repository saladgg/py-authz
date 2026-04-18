from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass
class AuditEvent:
    """
    Represents a single audit log event.
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

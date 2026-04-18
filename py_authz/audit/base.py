from typing import Protocol

from py_authz.audit.types import AuditEvent


class AuditLogger(Protocol):
    """
    Interface for audit logging backends.
    """

    async def log(self, event: AuditEvent) -> None: ...

from dataclasses import dataclass


@dataclass
class TenantContext:
    """
    Represents a tenant in the system.
    """

    id: str
    store_id: str

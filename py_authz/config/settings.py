# Configuration management

from pydantic import BaseModel


class Settings(BaseModel):
    """py-authz configuration."""

    openfga_url: str = "http://localhost:8080"

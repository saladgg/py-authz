# Configuration management

from pydantic import BaseSettings

class Settings(BaseSettings):
    """py-authz configuration."""
    openfga_url: str = "http://localhost:8080"

    class Config:
        env_prefix = "AUTHZ_"

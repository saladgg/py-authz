from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Mapping, Optional


@dataclass(frozen=True)
class IDToken:
    sub: str
    email: Optional[str] = None
    preferred_username: Optional[str] = None
    realm_access: Optional[Mapping[str, Any]] = None
    resource_access: Optional[Mapping[str, Any]] = None


@dataclass(frozen=True)
class AccessToken:
    raw: str
    subject: Optional[str] = None
    email: Optional[str] = None
    scope: Optional[str] = None


@dataclass(frozen=True)
class Principal:
    subject: str
    email: Optional[str] = None
    username: Optional[str] = None
    claims: Mapping[str, Any] | None = None
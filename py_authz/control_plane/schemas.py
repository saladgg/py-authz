"""Request/response bodies. Responses are mostly plain `dict`s built in
each route (FastAPI serializes those directly) — `pydantic` models here
are for request *validation* only, where a malformed body should be
rejected before it reaches a route's own logic."""

from pydantic import BaseModel, Field

from py_authz.control_plane.scopes import Scope
from py_authz.core.types import Resource

#: Ceiling for every list endpoint's `limit` (REL3-15). There was none, so
#: `?limit=100000000` loaded an entire table into API memory, and a
#: negative value reached asyncpg as a 500.
MAX_PAGE_SIZE = 500


class TenantCreateRequest(BaseModel):
    tenant_id: str


class ServiceAccountCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    #: Validated against the closed `Scope` enum (SEC3-1) — an unknown
    #: or misspelled scope is a 422, not a silently useless string.
    scopes: list[Scope] = Field(default_factory=list)


class TupleRef(BaseModel):
    type: str
    id: str

    def to_resource(self) -> Resource:
        """The core `Resource` this names. Routes pass that to
        `Authz.grant`/`revoke`, rather than this model duck-typed as one
        (ARCH3-17)."""
        return Resource(type=self.type, id=self.id)


class GrantRevokeRequest(BaseModel):
    """Body for `POST /tenants/{id}/grants` / `.../revokes`. `reason` is
    mandatory — CP-8's own requirement — and lands in the resulting audit
    event's `reason_data` (see `Authz.grant`/`revoke`'s `reason` arg)."""

    user: str
    relation: str
    object: TupleRef
    reason: str = Field(min_length=1, max_length=2000)


class ModelRollbackRequest(BaseModel):
    version_id: int


class MigrationRequest(BaseModel):
    dry_run: bool = False
    all_tenants: bool = False
    tenant_ids: list[str] | None = None


class CacheInvalidateRequest(BaseModel):
    """Exactly one of `key`/`tenant_id`/`user_id` (`user_id` may be
    combined with `tenant_id` to scope it to one tenant's cached
    decisions for that user — see `RedisCache.delete_by_fragment()`)."""

    key: str | None = None
    tenant_id: str | None = None
    user_id: str | None = None

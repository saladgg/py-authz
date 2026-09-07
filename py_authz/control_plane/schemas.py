"""Request/response bodies. Responses are mostly plain `dict`s built in
each route (FastAPI serializes those directly) — `pydantic` models here
are for request *validation* only, where a malformed body should be
rejected before it reaches a route's own logic."""

from pydantic import BaseModel, Field


class TenantCreateRequest(BaseModel):
    tenant_id: str


class ServiceAccountCreateRequest(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    scopes: list[str] = Field(default_factory=list)


class TupleRef(BaseModel):
    type: str
    id: str

    def to_fga_object(self) -> str:
        return f"{self.type}:{self.id}"


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

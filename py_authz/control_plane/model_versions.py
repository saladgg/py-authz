"""
Model version history (CP-6): `model_versions`
(`storage/sql/0006_model_versions.sql`) — append-only, unlike
`tenant_models` (which keeps meaning "current" and is overwritten on
every sync). This is the history `tenant_models` never had.

Recording a version is this module's only write path; syncing/rolling
back a model is `ModelSync`'s job (reused, not reimplemented — see
`routes/models.py`), this module only remembers what happened.
"""

import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import asyncpg

from py_authz.core.exceptions import ConfigurationError

_NOT_CONNECTED = (
    "ModelVersionStore is not connected — call `await store.connect()` first, "
    "or use it as an async context manager."
)


@dataclass(frozen=True)
class ModelVersion:
    id: int
    tenant_id: str | None
    model_id: str
    schema_json: dict[str, Any]
    change_summary: str | None
    created_by: str | None
    created_at: datetime


class ModelVersionStore:
    def __init__(
        self,
        dsn: str,
        *,
        pool_min_size: int = 5,
        pool_max_size: int = 5,
        command_timeout: float | None = 5.0,
    ):
        self.dsn = dsn
        self.pool_min_size = pool_min_size
        self.pool_max_size = pool_max_size
        self.command_timeout = command_timeout
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        if self._pool is not None:
            return
        self._pool = await asyncpg.create_pool(
            self.dsn,
            min_size=self.pool_min_size,
            max_size=self.pool_max_size,
            command_timeout=self.command_timeout,
        )

    async def close(self) -> None:
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def __aenter__(self) -> "ModelVersionStore":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED)
        return self._pool

    @staticmethod
    def _from_row(row) -> ModelVersion:
        return ModelVersion(
            id=row["id"],
            tenant_id=row["tenant_id"],
            model_id=row["model_id"],
            schema_json=json.loads(row["schema_json"]),
            change_summary=row["change_summary"],
            created_by=row["created_by"],
            created_at=row["created_at"],
        )

    async def record(
        self,
        *,
        tenant_id: str | None,
        model_id: str,
        schema_json: dict[str, Any],
        change_summary: str | None,
        created_by: str | None,
    ) -> ModelVersion:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO model_versions
                    (tenant_id, model_id, schema_json, change_summary, created_by)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                """,
                tenant_id,
                model_id,
                json.dumps(schema_json),
                change_summary,
                created_by,
            )
        return self._from_row(row)

    async def history(
        self, tenant_id: str | None, *, limit: int = 50, offset: int = 0
    ) -> list[ModelVersion]:
        """Newest-first history for `tenant_id` (or the global/
        single-tenant history, when `tenant_id` is `None`)."""
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            if tenant_id is None:
                rows = await conn.fetch(
                    "SELECT * FROM model_versions WHERE tenant_id IS NULL "
                    "ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM model_versions WHERE tenant_id = $1 "
                    "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    tenant_id,
                    limit,
                    offset,
                )
        return [self._from_row(row) for row in rows]

    async def get(self, version_id: int) -> ModelVersion | None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow("SELECT * FROM model_versions WHERE id = $1", version_id)
        return self._from_row(row) if row else None

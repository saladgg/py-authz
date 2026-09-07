"""
Async job system (CP-7) wrapping `sync`/`migrate`/`provision`/
`deprovision` — the same operations the CLI already exposes, but a
control-plane API route can't block for as long as a same-shape CLI
invocation takes (potentially minutes for an all-tenants migration).

A route inserts a `pending` `control_plane_jobs` row via `JobRunner.submit()`,
which kicks off the work as a background `asyncio.create_task` (a single
process is sufficient for v1 — see the architecture doc's open questions;
a real work queue is future work if the control-plane API ever needs more
than one instance) and updates the row to `running`/`succeeded`/`failed`
as it progresses. `GET /migrations/{job_id}` (see `routes/migrations.py`)
polls the row this produces.
"""

import asyncio
import json
import uuid
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Any

import asyncpg

from py_authz.core.exceptions import ConfigurationError
from py_authz.core.logging import logger

_NOT_CONNECTED = (
    "JobStore is not connected — call `await store.connect()` first, "
    "or use it as an async context manager."
)

#: `control_plane_jobs.status` values, in the order a job passes through
#: them (barring the `pending` -> `failed` shortcut a submission-time
#: validation error can take).
PENDING, RUNNING, SUCCEEDED, FAILED = "pending", "running", "succeeded", "failed"


@dataclass(frozen=True)
class Job:
    id: str
    kind: str
    status: str
    params: dict[str, Any] | None
    result: dict[str, Any] | None
    initiated_by: str | None
    started_at: datetime | None
    finished_at: datetime | None
    created_at: datetime


def _new_id() -> str:
    return f"job_{uuid.uuid4().hex}"


class JobStore:
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

    async def __aenter__(self) -> "JobStore":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _require_pool(self) -> asyncpg.Pool:
        if self._pool is None:
            raise ConfigurationError(_NOT_CONNECTED)
        return self._pool

    @staticmethod
    def _from_row(row) -> Job:
        return Job(
            id=row["id"],
            kind=row["kind"],
            status=row["status"],
            params=json.loads(row["params_json"]) if row["params_json"] is not None else None,
            result=json.loads(row["result_json"]) if row["result_json"] is not None else None,
            initiated_by=row["initiated_by"],
            started_at=row["started_at"],
            finished_at=row["finished_at"],
            created_at=row["created_at"],
        )

    async def create(self, *, kind: str, params: dict[str, Any], initiated_by: str | None) -> Job:
        pool = self._require_pool()
        job_id = _new_id()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO control_plane_jobs (id, kind, status, params_json, initiated_by)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *
                """,
                job_id,
                kind,
                PENDING,
                json.dumps(params),
                initiated_by,
            )
        return self._from_row(row)

    async def mark_running(self, job_id: str) -> None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                "UPDATE control_plane_jobs SET status = $2, started_at = now() WHERE id = $1",
                job_id,
                RUNNING,
            )

    async def mark_finished(self, job_id: str, *, status: str, result: dict[str, Any]) -> None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            await conn.execute(
                """
                UPDATE control_plane_jobs
                SET status = $2, result_json = $3, finished_at = now()
                WHERE id = $1
                """,
                job_id,
                status,
                json.dumps(result),
            )

    async def get(self, job_id: str) -> Job | None:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            row = await conn.fetchrow("SELECT * FROM control_plane_jobs WHERE id = $1", job_id)
        return self._from_row(row) if row else None

    async def list(self, *, kind: str | None = None, limit: int = 50, offset: int = 0) -> list[Job]:
        pool = self._require_pool()
        async with pool.acquire(timeout=self.command_timeout) as conn:
            if kind is None:
                rows = await conn.fetch(
                    "SELECT * FROM control_plane_jobs ORDER BY created_at DESC LIMIT $1 OFFSET $2",
                    limit,
                    offset,
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM control_plane_jobs WHERE kind = $1 "
                    "ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                    kind,
                    limit,
                    offset,
                )
        return [self._from_row(row) for row in rows]


class JobRunner:
    """
    Runs a job's work as a background `asyncio.create_task`, updating its
    `JobStore` row as it progresses. One `JobRunner` per control-plane
    API process — construct it once (see `app.py`'s lifespan) and reuse
    it across every job-submitting route.
    """

    def __init__(self, store: JobStore):
        self.store = store
        self._tasks: set[asyncio.Task] = set()

    async def submit(
        self,
        *,
        kind: str,
        params: dict[str, Any],
        initiated_by: str | None,
        work: Callable[[], Awaitable[dict[str, Any]]],
    ) -> Job:
        """
        Create the `pending` row and start `work()` in the background.
        Returns immediately with the (still-`pending`) `Job` — poll
        `JobStore.get(job.id)` for progress.
        """
        job = await self.store.create(kind=kind, params=params, initiated_by=initiated_by)
        task = asyncio.create_task(self._run(job.id, work))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)
        return job

    async def _run(self, job_id: str, work: Callable[[], Awaitable[dict[str, Any]]]) -> None:
        await self.store.mark_running(job_id)
        try:
            result = await work()
            await self.store.mark_finished(job_id, status=SUCCEEDED, result=result)
        except Exception as exc:
            logger.exception(json.dumps({"event": "control_plane_job_failed", "job_id": job_id}))
            await self.store.mark_finished(
                job_id,
                status=FAILED,
                result={"error": str(exc), "error_type": type(exc).__name__},
            )

    async def aclose(self) -> None:
        """Await every in-flight job's background task — call on process
        shutdown so it doesn't race ahead of jobs still updating their row."""
        if self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

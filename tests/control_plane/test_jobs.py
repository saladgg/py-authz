"""Tests for py_authz.control_plane.jobs (CP-7)."""

import asyncio
from contextlib import asynccontextmanager

import pytest

from py_authz.control_plane import jobs as jobs_module
from py_authz.control_plane.jobs import FAILED, PENDING, RUNNING, SUCCEEDED, JobRunner, JobStore
from py_authz.core.exceptions import ConfigurationError


class FakeConnection:
    def __init__(self, pool):
        self.pool = pool

    async def fetchrow(self, query, *args):
        return self.pool._apply(query, args)

    async def fetch(self, query, *args):
        rows = sorted(self.pool.rows.values(), key=lambda r: r["created_at"], reverse=True)
        if "WHERE kind" in query:
            kind = args[0]
            rows = [r for r in rows if r["kind"] == kind]
        return rows

    async def execute(self, query, *args):
        self.pool._apply(query, args)


class FakePool:
    def __init__(self):
        self.rows: dict[str, dict] = {}
        self.closed = False
        self._counter = 0

    @asynccontextmanager
    async def acquire(self, timeout=None):
        yield FakeConnection(self)

    async def close(self):
        self.closed = True

    def _apply(self, query, args):
        if "INSERT INTO control_plane_jobs" in query:
            job_id, kind, status, params_json, initiated_by = args
            self._counter += 1
            row = {
                "id": job_id,
                "kind": kind,
                "status": status,
                "params_json": params_json,
                "result_json": None,
                "initiated_by": initiated_by,
                "started_at": None,
                "finished_at": None,
                "created_at": self._counter,
            }
            self.rows[job_id] = row
            return row
        if "SET status" in query and "started_at" in query:
            job_id, status = args
            row = self.rows[job_id]
            row["status"] = status
            row["started_at"] = "now"
            return None
        if "SET status" in query and "result_json" in query:
            job_id, status, result_json = args
            row = self.rows[job_id]
            row["status"] = status
            row["result_json"] = result_json
            row["finished_at"] = "now"
            return None
        if "SELECT * FROM control_plane_jobs WHERE id" in query:
            (job_id,) = args
            return self.rows.get(job_id)
        return None


@pytest.fixture
def patched_asyncpg(monkeypatch):
    pool = FakePool()

    async def _create_pool(dsn, **kwargs):
        return pool

    fake_module = type("asyncpg_stub", (), {"create_pool": staticmethod(_create_pool)})
    monkeypatch.setattr(jobs_module, "asyncpg", fake_module)
    return pool


@pytest.mark.asyncio
async def test_create_starts_pending(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()

    job = await store.create(kind="migrate", params={"a": 1}, initiated_by="user:op")

    assert job.status == PENDING
    assert job.params == {"a": 1}
    assert job.result is None


@pytest.mark.asyncio
async def test_lifecycle_transitions(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    job = await store.create(kind="migrate", params={}, initiated_by=None)

    await store.mark_running(job.id)
    running = await store.get(job.id)
    assert running.status == RUNNING

    await store.mark_finished(job.id, status=SUCCEEDED, result={"ok": True})
    finished = await store.get(job.id)
    assert finished.status == SUCCEEDED
    assert finished.result == {"ok": True}


@pytest.mark.asyncio
async def test_runner_submit_runs_work_and_marks_succeeded(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    runner = JobRunner(store)

    async def work():
        return {"done": True}

    job = await runner.submit(kind="sync", params={}, initiated_by="user:op", work=work)
    assert job.status == PENDING  # returns immediately, before the background task runs

    await runner.aclose()

    finished = await store.get(job.id)
    assert finished.status == SUCCEEDED
    assert finished.result == {"done": True}


@pytest.mark.asyncio
async def test_runner_marks_failed_on_exception_without_losing_the_job(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    runner = JobRunner(store)

    async def work():
        raise RuntimeError("boom")

    job = await runner.submit(kind="sync", params={}, initiated_by=None, work=work)
    await runner.aclose()

    finished = await store.get(job.id)
    assert finished.status == FAILED
    assert finished.result["error"] == "boom"
    assert finished.result["error_type"] == "RuntimeError"


@pytest.mark.asyncio
async def test_runner_aclose_waits_for_in_flight_jobs(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    runner = JobRunner(store)

    started = asyncio.Event()

    async def slow_work():
        started.set()
        await asyncio.sleep(0.01)
        return {"slow": True}

    job = await runner.submit(kind="sync", params={}, initiated_by=None, work=slow_work)
    await started.wait()
    await runner.aclose()

    finished = await store.get(job.id)
    assert finished.status == SUCCEEDED


@pytest.mark.asyncio
async def test_list_filters_by_kind(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    await store.create(kind="migrate", params={}, initiated_by=None)
    await store.create(kind="sync", params={}, initiated_by=None)

    migrate_jobs = await store.list(kind="migrate")

    assert len(migrate_jobs) == 1
    assert migrate_jobs[0].kind == "migrate"


@pytest.mark.asyncio
async def test_list_without_a_kind_filter_returns_everything(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    await store.create(kind="migrate", params={}, initiated_by=None)
    await store.create(kind="sync", params={}, initiated_by=None)

    all_jobs = await store.list()

    assert {j.kind for j in all_jobs} == {"migrate", "sync"}


# -------------------------------------------------------------------
# connect()/close()/context-manager/_require_pool — connection lifecycle
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_connect_is_idempotent(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    pool_after_first_connect = store._pool

    await store.connect()  # a second call must not replace the pool

    assert store._pool is pool_after_first_connect


@pytest.mark.asyncio
async def test_close_clears_the_pool(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()

    await store.close()

    assert store._pool is None
    assert patched_asyncpg.closed is True


@pytest.mark.asyncio
async def test_close_without_ever_connecting_is_a_noop():
    store = JobStore(dsn="postgres://fake")

    await store.close()  # must not raise

    assert store._pool is None


@pytest.mark.asyncio
async def test_used_as_an_async_context_manager(patched_asyncpg):
    async with JobStore(dsn="postgres://fake") as store:
        job = await store.create(kind="sync", params={}, initiated_by=None)
        assert job.status == PENDING

    assert store._pool is None  # __aexit__ closed it


@pytest.mark.asyncio
async def test_operations_before_connect_raise_configuration_error():
    store = JobStore(dsn="postgres://fake")

    with pytest.raises(ConfigurationError, match="not connected"):
        await store.create(kind="sync", params={}, initiated_by=None)


# -------------------------------------------------------------------
# JobRunner.aclose() with no in-flight jobs
# -------------------------------------------------------------------


@pytest.mark.asyncio
async def test_runner_aclose_with_no_jobs_submitted_is_a_noop(patched_asyncpg):
    store = JobStore(dsn="postgres://fake")
    await store.connect()
    runner = JobRunner(store)

    await runner.aclose()  # must not raise even though nothing was ever submitted

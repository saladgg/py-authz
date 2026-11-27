"""Tests for py_authz.audit.batching.BatchingAuditLogger (REL3-16)."""

import asyncio
from datetime import datetime

import pytest

from py_authz.audit.batching import BatchingAuditLogger
from py_authz.audit.types import AuditEvent
from py_authz.core.metrics import Metrics


def _event(i: int) -> AuditEvent:
    return AuditEvent(
        timestamp=datetime(2026, 1, 1),
        tenant_id="t",
        user_id=f"user:{i}",
        action="view",
        resource="doc:1",
        allowed=True,
    )


class ManyLogger:
    def __init__(self, fail: bool = False):
        self.batches: list[list[AuditEvent]] = []
        self.fail = fail
        self.connected = self.closed = False

    async def log_many(self, events):
        if self.fail:
            raise RuntimeError("db down")
        self.batches.append(list(events))

    async def log(self, event):  # pragma: no cover - log_many is preferred
        raise AssertionError("log_many should be used")

    async def connect(self):
        self.connected = True

    async def close(self):
        self.closed = True


class SingleLogger:
    def __init__(self, fail_on: str | None = None):
        self.events: list[AuditEvent] = []
        self.fail_on = fail_on

    async def log(self, event):
        if event.user_id == self.fail_on:
            raise RuntimeError("bad row")
        self.events.append(event)


@pytest.mark.asyncio
async def test_events_are_written_in_batches_via_log_many():
    inner = ManyLogger()
    logger = BatchingAuditLogger(inner, max_batch_size=3, flush_interval=0.05)

    for i in range(7):
        await logger.log(_event(i))
    await logger.flush()

    assert [len(b) for b in inner.batches] == [3, 3, 1]
    assert [e.user_id for b in inner.batches for e in b] == [f"user:{i}" for i in range(7)]
    await logger.close()


@pytest.mark.asyncio
async def test_a_partial_batch_is_written_after_flush_interval():
    inner = ManyLogger()
    logger = BatchingAuditLogger(inner, max_batch_size=100, flush_interval=0.01)

    await logger.log(_event(1))
    for _ in range(100):
        if inner.batches:
            break
        await asyncio.sleep(0.005)

    assert len(inner.batches) == 1
    await logger.close()


@pytest.mark.asyncio
async def test_batch_is_cut_off_once_flush_interval_has_elapsed():
    # Events are already queued, but the flush interval is shorter than the
    # time between two reads: each batch is written as soon as its deadline
    # passes instead of waiting to fill up to max_batch_size.
    inner = ManyLogger()
    logger = BatchingAuditLogger(inner, max_batch_size=100, flush_interval=1e-9)

    for i in range(3):  # the worker hasn't run yet: all three are queued
        await logger.log(_event(i))
    await logger.flush()

    assert [len(b) for b in inner.batches] == [1, 1, 1]
    assert [e.user_id for b in inner.batches for e in b] == ["user:0", "user:1", "user:2"]
    await logger.close()


@pytest.mark.asyncio
async def test_full_queue_drops_and_counts():
    metrics = Metrics()
    inner = ManyLogger()
    logger = BatchingAuditLogger(inner, max_queue_size=2, metrics=metrics)

    for i in range(5):  # the worker hasn't run yet: the queue holds 2
        await logger.log(_event(i))

    assert logger.dropped == 3
    assert metrics.counters["audit_events_dropped_total"] == 3
    await logger.close()
    assert sum(len(b) for b in inner.batches) == 2


@pytest.mark.asyncio
async def test_failed_batch_is_counted_and_the_worker_keeps_going():
    metrics = Metrics()
    inner = ManyLogger(fail=True)
    logger = BatchingAuditLogger(inner, metrics=metrics, flush_interval=0.01)

    await logger.log(_event(1))
    await logger.flush()
    inner.fail = False
    await logger.log(_event(2))
    await logger.flush()

    assert logger.failed == 1
    assert metrics.counters["audit_events_failed_total"] == 1
    assert [e.user_id for b in inner.batches for e in b] == ["user:2"]
    await logger.close()


@pytest.mark.asyncio
async def test_falls_back_to_log_per_event_and_isolates_failures():
    inner = SingleLogger(fail_on="user:1")
    logger = BatchingAuditLogger(inner, flush_interval=0.01)

    for i in range(3):
        await logger.log(_event(i))
    await logger.close()

    assert [e.user_id for e in inner.events] == ["user:0", "user:2"]
    assert logger.failed == 1


@pytest.mark.asyncio
async def test_context_manager_connects_flushes_and_closes_inner():
    inner = ManyLogger()
    async with BatchingAuditLogger(inner, flush_interval=0.01) as logger:
        assert inner.connected
        await logger.log(_event(1))

    assert inner.closed
    assert len(inner.batches) == 1
    # After close, events are dropped rather than queued forever.
    await logger.log(_event(2))
    assert logger.dropped == 1
    await logger.close()  # idempotent


@pytest.mark.asyncio
async def test_close_inner_false_leaves_inner_alone():
    inner = ManyLogger()
    logger = BatchingAuditLogger(inner, close_inner=False)
    await logger.connect()
    await logger.close()

    assert not inner.connected and not inner.closed


@pytest.mark.asyncio
async def test_flush_and_close_without_any_event():
    logger = BatchingAuditLogger(ManyLogger())
    await logger.flush()
    await logger.close()


@pytest.mark.parametrize(
    "kwargs", [{"max_batch_size": 0}, {"max_queue_size": 0}, {"flush_interval": 0}]
)
def test_rejects_non_positive_settings(kwargs):
    with pytest.raises(ValueError):
        BatchingAuditLogger(ManyLogger(), **kwargs)

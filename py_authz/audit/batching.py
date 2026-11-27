"""
`BatchingAuditLogger`: a queue in front of another audit logger (REL3-16).

`AuthzEngine` writes one audit event per decision (cache hits included).
Writing each one with its own pooled INSERT saturates a 10-connection pool
at a few thousand checks per second, and the engine then starts dropping
events. This wrapper makes `log()` a non-blocking enqueue and writes the
queue in batches (through the inner logger's `log_many()` when it has one,
e.g. `PostgresAuditLogger`'s `COPY`).

Delivery is best-effort, like every audit path here: when the queue is
full the event is dropped and counted as `audit_events_dropped_total`; a
batch the inner logger fails to write is counted as
`audit_events_failed_total`. Call `flush()` to wait for everything queued
so far, and `close()` (or use `async with`) on shutdown.
"""

import asyncio
import contextlib
import logging
from collections.abc import Sequence

from py_authz.audit.types import AuditEvent

logger = logging.getLogger("py_authz.audit")


class BatchingAuditLogger:
    def __init__(
        self,
        inner,
        *,
        max_batch_size: int = 500,
        flush_interval: float = 0.2,
        max_queue_size: int = 10_000,
        metrics=None,
        close_inner: bool = True,
    ):
        """
        Args:
            inner: The audit logger that does the writing. Its
                `log_many(events)` is used if present, otherwise `log()`
                per event.
            max_batch_size: Most events written in one call.
            flush_interval: Longest an event waits (seconds) for a batch
                to fill before it's written anyway.
            max_queue_size: Events buffered before new ones are dropped.
            metrics: Optional `incr(name, amount=1)` sink (see
                `core/metrics.py`).
            close_inner: Whether `close()`/`connect()` also manage
                `inner`'s lifecycle.
        """
        if max_batch_size < 1 or max_queue_size < 1 or flush_interval <= 0:
            raise ValueError("max_batch_size, max_queue_size and flush_interval must be positive")
        self.inner = inner
        self.max_batch_size = max_batch_size
        self.flush_interval = flush_interval
        self.max_queue_size = max_queue_size
        self.metrics = metrics
        self.close_inner = close_inner
        self.dropped = 0
        self.failed = 0
        self._queue: asyncio.Queue[AuditEvent] | None = None
        self._worker: asyncio.Task | None = None
        self._closed = False

    # -- lifecycle -----------------------------------------------------

    async def connect(self) -> None:
        if self.close_inner and hasattr(self.inner, "connect"):
            await self.inner.connect()

    async def __aenter__(self) -> "BatchingAuditLogger":
        await self.connect()
        return self

    async def __aexit__(self, *exc_info) -> None:
        await self.close()

    def _ensure_worker(self) -> asyncio.Queue[AuditEvent]:
        # Created lazily so the queue and task belong to the loop that
        # actually logs, not whichever one constructed this object.
        if self._queue is None:
            self._queue = asyncio.Queue(maxsize=self.max_queue_size)
        if self._worker is None or self._worker.done():
            self._worker = asyncio.ensure_future(self._run())
        return self._queue

    async def flush(self) -> None:
        """Wait until every event queued so far has been written (or failed)."""
        if self._queue is not None and self._worker is not None:
            await self._queue.join()

    async def close(self) -> None:
        """Flush, stop the worker, then close `inner` (if `close_inner`)."""
        if self._closed:
            return
        self._closed = True
        await self.flush()
        if self._worker is not None:
            self._worker.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._worker
            self._worker = None
        if self.close_inner and hasattr(self.inner, "close"):
            await self.inner.close()

    # -- writing -------------------------------------------------------

    async def log(self, event: AuditEvent) -> None:
        if self._closed:
            self._count_dropped(1, "closed")
            return
        queue = self._ensure_worker()
        try:
            queue.put_nowait(event)
        except asyncio.QueueFull:
            self._count_dropped(1, "queue_full")

    def _count_dropped(self, n: int, why: str) -> None:
        # Log the first drop and then every 1000th, so a sustained outage
        # doesn't turn into one warning line per authorization check.
        before = self.dropped
        self.dropped += n
        if self.metrics:
            self.metrics.incr("audit_events_dropped_total", n)
        if before == 0 or before // 1000 != self.dropped // 1000:
            logger.warning("audit events dropped (%s); %d dropped so far", why, self.dropped)

    async def _run(self) -> None:
        queue = self._queue
        if queue is None:  # pragma: no cover - set by `_ensure_worker` first
            return
        loop = asyncio.get_running_loop()
        while True:
            batch = [await queue.get()]
            deadline = loop.time() + self.flush_interval
            while len(batch) < self.max_batch_size:
                timeout = deadline - loop.time()
                if timeout <= 0:
                    break
                try:
                    batch.append(await asyncio.wait_for(queue.get(), timeout))
                except TimeoutError:
                    break
            try:
                await self._write(batch)
            finally:
                for _ in batch:
                    queue.task_done()

    async def _write(self, batch: Sequence[AuditEvent]) -> None:
        log_many = getattr(self.inner, "log_many", None)
        if log_many is not None:
            try:
                await log_many(batch)
            except Exception:
                self._count_failed(len(batch))
            return
        for event in batch:
            try:
                await self.inner.log(event)
            except Exception:
                self._count_failed(1)

    def _count_failed(self, n: int) -> None:
        self.failed += n
        if self.metrics:
            self.metrics.incr("audit_events_failed_total", n)
        logger.exception("audit write failed (%d events)", n)

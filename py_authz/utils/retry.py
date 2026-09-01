"""
Shared async retry helper.

Extracted from `clients/openfga.py`'s inline retry loop so the same
bounded-exponential-backoff behavior is written (and tested) once instead
of hand-rolled per call site.
"""

import asyncio
from collections.abc import Awaitable, Callable


async def retry_async[T](
    func: Callable[[], Awaitable[T]],
    *,
    retryable: tuple[type[Exception], ...],
    max_retries: int = 2,
    base_delay: float = 0.1,
) -> T:
    """
    Call `func()`, retrying on any exception in `retryable` with
    exponential backoff (`base_delay * 2**attempt`, `attempt` starting at
    1 for the first retry) up to `max_retries` additional attempts.

    Any exception NOT in `retryable` propagates immediately, on the first
    attempt, with no retry. Once `max_retries` is exhausted, the last
    retryable exception propagates unchanged (same type, same traceback)
    — callers that need to translate it to a domain-specific exception
    should do so in their own `except` block around this call, exactly as
    they would around a non-retried call.

    Args:
        func: zero-argument async callable to invoke (and retry).
        retryable: exception types that trigger a retry.
        max_retries: number of *additional* attempts after the first.
        base_delay: seconds; the backoff multiplier for attempt 1.
    """
    attempt = 0
    while True:
        try:
            return await func()
        except retryable:
            if attempt >= max_retries:
                raise
            attempt += 1
            await asyncio.sleep(base_delay * (2**attempt))

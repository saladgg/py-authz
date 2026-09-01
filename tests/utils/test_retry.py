import pytest

from py_authz.utils.retry import retry_async


class Flaky:
    def __init__(self, fail_times: int, exc: Exception):
        self.calls = 0
        self.fail_times = fail_times
        self.exc = exc

    async def __call__(self):
        self.calls += 1
        if self.calls <= self.fail_times:
            raise self.exc
        return "ok"


@pytest.mark.asyncio
async def test_succeeds_on_first_try_without_retrying():
    flaky = Flaky(fail_times=0, exc=TimeoutError())

    result = await retry_async(flaky, retryable=(TimeoutError,))

    assert result == "ok"
    assert flaky.calls == 1


@pytest.mark.asyncio
async def test_retries_up_to_max_retries_then_succeeds():
    flaky = Flaky(fail_times=2, exc=TimeoutError())

    result = await retry_async(flaky, retryable=(TimeoutError,), max_retries=2, base_delay=0.001)

    assert result == "ok"
    assert flaky.calls == 3  # initial attempt + 2 retries


@pytest.mark.asyncio
async def test_reraises_original_exception_once_retries_exhausted():
    flaky = Flaky(fail_times=99, exc=TimeoutError("still timing out"))

    with pytest.raises(TimeoutError, match="still timing out"):
        await retry_async(flaky, retryable=(TimeoutError,), max_retries=2, base_delay=0.001)

    assert flaky.calls == 3  # initial attempt + 2 retries, then gives up


@pytest.mark.asyncio
async def test_non_retryable_exception_propagates_immediately():
    flaky = Flaky(fail_times=99, exc=ValueError("not retryable"))

    with pytest.raises(ValueError, match="not retryable"):
        await retry_async(flaky, retryable=(TimeoutError,), max_retries=5, base_delay=0.001)

    assert flaky.calls == 1  # no retry attempted at all

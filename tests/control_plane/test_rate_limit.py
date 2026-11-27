"""Tests for py_authz.control_plane.rate_limit (CP-16)."""

import time

import pytest

from py_authz.control_plane.rate_limit import (
    InMemoryRateLimiter,
    RateLimitPolicy,
    RedisRateLimiter,
)


class FakeRedis:
    """Minimal INCR/EXPIRE/GET/SET/DELETE double — enough to exercise
    `RedisRateLimiter`'s exact command sequence."""

    def __init__(self):
        self.store: dict[str, str] = {}
        self.ttls: dict[str, int] = {}

    async def incr(self, key: str) -> int:
        self.store[key] = str(int(self.store.get(key, "0")) + 1)
        return int(self.store[key])

    async def expire(self, key: str, seconds: int) -> None:
        self.ttls[key] = seconds

    async def get(self, key: str) -> str | None:
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        self.store[key] = value
        if ex is not None:
            self.ttls[key] = ex

    async def delete(self, *keys: str) -> None:
        for key in keys:
            self.store.pop(key, None)
            self.ttls.pop(key, None)


# ----------------------------------------------------------------------
# InMemoryRateLimiter
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_in_memory_not_locked_out_initially():
    limiter = InMemoryRateLimiter()
    assert await limiter.is_locked_out("sa_1") is False


@pytest.mark.asyncio
async def test_in_memory_locks_out_after_max_attempts():
    limiter = InMemoryRateLimiter(RateLimitPolicy(max_failed_attempts=3, lockout_seconds=60))

    for _ in range(2):
        await limiter.record_failure("sa_1")
    assert await limiter.is_locked_out("sa_1") is False

    await limiter.record_failure("sa_1")  # 3rd failure crosses the threshold
    assert await limiter.is_locked_out("sa_1") is True


@pytest.mark.asyncio
async def test_in_memory_lockout_is_per_key():
    limiter = InMemoryRateLimiter(RateLimitPolicy(max_failed_attempts=1, lockout_seconds=60))

    await limiter.record_failure("sa_1")

    assert await limiter.is_locked_out("sa_1") is True
    assert await limiter.is_locked_out("sa_2") is False


@pytest.mark.asyncio
async def test_in_memory_record_success_resets_failures():
    limiter = InMemoryRateLimiter(RateLimitPolicy(max_failed_attempts=2, lockout_seconds=60))

    await limiter.record_failure("sa_1")
    await limiter.record_success("sa_1")
    await limiter.record_failure("sa_1")

    # Only one failure since the reset — must not be locked out yet.
    assert await limiter.is_locked_out("sa_1") is False


@pytest.mark.asyncio
async def test_in_memory_lockout_expires_after_window(monkeypatch):
    import time

    limiter = InMemoryRateLimiter(RateLimitPolicy(max_failed_attempts=1, lockout_seconds=60))
    await limiter.record_failure("sa_1")
    assert await limiter.is_locked_out("sa_1") is True

    # Fast-forward past the lockout window.
    real_monotonic = time.monotonic
    monkeypatch.setattr(time, "monotonic", lambda: real_monotonic() + 61)

    assert await limiter.is_locked_out("sa_1") is False


# ----------------------------------------------------------------------
# RedisRateLimiter
# ----------------------------------------------------------------------


@pytest.mark.asyncio
async def test_redis_not_locked_out_initially():
    limiter = RedisRateLimiter(FakeRedis())
    assert await limiter.is_locked_out("sa_1") is False


@pytest.mark.asyncio
async def test_redis_locks_out_after_max_attempts_and_sets_ttl():
    redis = FakeRedis()
    limiter = RedisRateLimiter(redis, RateLimitPolicy(max_failed_attempts=2, lockout_seconds=120))

    await limiter.record_failure("sa_1")
    assert await limiter.is_locked_out("sa_1") is False

    await limiter.record_failure("sa_1")
    assert await limiter.is_locked_out("sa_1") is True
    assert redis.ttls[limiter._locked_key("sa_1")] == 120
    assert redis.ttls[limiter._failures_key("sa_1")] == 120


@pytest.mark.asyncio
async def test_redis_record_success_clears_both_keys():
    redis = FakeRedis()
    limiter = RedisRateLimiter(redis, RateLimitPolicy(max_failed_attempts=1, lockout_seconds=60))

    await limiter.record_failure("sa_1")
    assert await limiter.is_locked_out("sa_1") is True

    await limiter.record_success("sa_1")

    assert await limiter.is_locked_out("sa_1") is False
    assert limiter._failures_key("sa_1") not in redis.store


@pytest.mark.asyncio
async def test_redis_lockout_is_per_key():
    redis = FakeRedis()
    limiter = RedisRateLimiter(redis, RateLimitPolicy(max_failed_attempts=1, lockout_seconds=60))

    await limiter.record_failure("sa_1")

    assert await limiter.is_locked_out("sa_1") is True
    assert await limiter.is_locked_out("sa_2") is False


@pytest.mark.asyncio
async def test_sweep_keeps_a_live_lockout_after_the_policy_is_shortened(monkeypatch):
    """A sweep only drops keys whose lockout has expired. Shortening the
    policy at runtime must not unlock a key that is still locked."""
    now = [1000.0]
    monkeypatch.setattr(time, "monotonic", lambda: now[0])
    limiter = InMemoryRateLimiter(RateLimitPolicy(max_failed_attempts=1, lockout_seconds=300))
    monkeypatch.setattr(limiter, "MAX_TRACKED_KEYS", 1)
    await limiter.record_failure("attacker")
    assert await limiter.is_locked_out("attacker")

    limiter.policy = RateLimitPolicy(max_failed_attempts=1, lockout_seconds=1)
    now[0] += 2
    await limiter.record_failure("other")  # over MAX_TRACKED_KEYS: sweeps

    assert await limiter.is_locked_out("attacker")

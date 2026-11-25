"""
Failed-attempt lockout for the service-account secret-verification path
(CP-16).

This is the one endpoint in the whole control-plane API — and in this
library as a whole — that authenticates a bearer secret directly against
a stored hash rather than delegating to an IdP (that's `OIDCJWTValidator`'s
job, for operator logins). The library's own documented stance
(`docs/architecture.md`, "Known sharp edges") is that it doesn't
rate-limit its own *outbound* calls and expects the host app to handle
that; this is the mirror case, *inbound*, and the control-plane API is
that host app for this one endpoint specifically — it can't defer this
to "someone else's problem" the way `check()`/`list_objects()` can.

The limiter itself is keyed on an opaque string. The control plane
passes `"<service-account id>|<client network>"` (SEC3-13, see
`auth.client_network()`): keying on the account id alone let anyone who
knew an SA id (auditors can list them, and every secret embeds one) keep
that SA locked out indefinitely. Keyed on both, a brute-force source only
locks out itself.
"""

import time
from dataclasses import dataclass
from typing import Protocol


@dataclass(frozen=True)
class RateLimitPolicy:
    #: Consecutive failures (within `lockout_seconds` of each other)
    #: before lockout kicks in.
    max_failed_attempts: int = 5
    #: Both the failure-counting window and the lockout duration once
    #: triggered — one knob is enough for a "minimum bar" implementation
    #: (see CP-16); a production deployment wanting them to differ can
    #: construct its own `RateLimitPolicy`-shaped policy.
    lockout_seconds: int = 300


class RateLimiter(Protocol):
    async def is_locked_out(self, key: str) -> bool: ...

    async def record_failure(self, key: str) -> None: ...

    async def record_success(self, key: str) -> None: ...


class InMemoryRateLimiter:
    """
    Single-process failure counter — matches this backlog's existing
    single-process-for-v1 assumption (see `jobs.JobRunner`'s own
    docstring). Not shared across multiple control-plane API instances;
    use `RedisRateLimiter` once more than one instance is running behind
    a load balancer, or a lockout on instance A wouldn't apply to
    instance B.
    """

    #: Sweep threshold (SEC3-9): once this many ids are tracked, entries
    #: whose window and lockout have both expired are dropped.
    MAX_TRACKED_KEYS = 10_000

    def __init__(self, policy: RateLimitPolicy | None = None):
        self.policy = policy or RateLimitPolicy()
        self._failure_times: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}

    def _sweep(self, now: float) -> None:
        window_start = now - self.policy.lockout_seconds
        for key in [k for k, ts in self._failure_times.items() if not ts or ts[-1] < window_start]:
            if self._locked_until.get(key, 0) <= now:
                self._failure_times.pop(key, None)
                self._locked_until.pop(key, None)

    async def is_locked_out(self, key: str) -> bool:
        locked_until = self._locked_until.get(key)
        if locked_until is None:
            return False
        if time.monotonic() >= locked_until:
            # Lockout expired — clear it (and the failure history that
            # triggered it) so a subsequent legitimate attempt isn't
            # penalized by attempts from before the lockout window.
            self._locked_until.pop(key, None)
            self._failure_times.pop(key, None)
            return False
        return True

    async def record_failure(self, key: str) -> None:
        now = time.monotonic()
        if len(self._failure_times) >= self.MAX_TRACKED_KEYS:
            self._sweep(now)
        window_start = now - self.policy.lockout_seconds
        attempts = [t for t in self._failure_times.get(key, []) if t >= window_start]
        attempts.append(now)
        self._failure_times[key] = attempts

        if len(attempts) >= self.policy.max_failed_attempts:
            self._locked_until[key] = now + self.policy.lockout_seconds

    async def record_success(self, key: str) -> None:
        self._failure_times.pop(key, None)
        self._locked_until.pop(key, None)


class RedisRateLimiter:
    """
    Shares lockout state across every control-plane API instance via
    Redis. Two keys per tracked id: a counter (`INCR`, `EXPIRE`d to the
    policy's window on first increment) and a lockout flag (set once the
    counter crosses the threshold, itself `EX`-expiring after
    `lockout_seconds` — no separate cleanup needed either way).
    """

    def __init__(
        self,
        client,
        policy: RateLimitPolicy | None = None,
        *,
        prefix: str = "py_authz:control_plane:ratelimit:",
    ):
        self._client = client
        self.policy = policy or RateLimitPolicy()
        self._prefix = prefix

    def _failures_key(self, key: str) -> str:
        return f"{self._prefix}{key}:failures"

    def _locked_key(self, key: str) -> str:
        return f"{self._prefix}{key}:locked"

    async def is_locked_out(self, key: str) -> bool:
        return bool(await self._client.get(self._locked_key(key)))

    async def record_failure(self, key: str) -> None:
        failures_key = self._failures_key(key)
        count = await self._client.incr(failures_key)
        if count == 1:
            # First failure in a fresh window — start the window's TTL.
            # A raced concurrent first-failure could both see count==1
            # (INCR is atomic per-call, but the EXPIRE isn't part of the
            # same atomic op) and both call EXPIRE with the same TTL —
            # harmless, since they'd set the same value either way.
            await self._client.expire(failures_key, self.policy.lockout_seconds)

        if count >= self.policy.max_failed_attempts:
            await self._client.set(self._locked_key(key), "1", ex=self.policy.lockout_seconds)

    async def record_success(self, key: str) -> None:
        await self._client.delete(self._failures_key(key), self._locked_key(key))

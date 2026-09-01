class Metrics:
    """
    Minimal in-process counters + duration observations.

    This is deliberately NOT a full metrics library — no bucketed
    histograms, no aggregation/export format, no backend integration. It
    exists so `AuthzEngine` has somewhere to report allow/deny counts and
    check latency without a hard dependency on any specific backend
    (Prometheus, StatsD, OpenTelemetry, ...). Wire `counters`/`durations`
    to your real metrics backend on a schedule, or pass your own object
    implementing `incr`/`observe` to `AuthzEngine(metrics=...)` instead of
    the module-level `metrics` singleton.
    """

    def __init__(self):
        self.counters: dict[str, int] = {}
        self.durations: dict[str, list[float]] = {}

    def incr(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def observe(self, name: str, value: float) -> None:
        """Record a single observation (e.g. a latency in milliseconds)
        under `name`, for later export as a histogram/summary."""
        self.durations.setdefault(name, []).append(value)


metrics = Metrics()

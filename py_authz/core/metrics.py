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

    def __init__(self, *, max_observations_per_metric: int | None = 10_000):
        """
        Args:
            max_observations_per_metric: caps how many raw observations
                `observe()` keeps per metric name — oldest dropped first
                (a simple ring buffer, not real downsampling/histogram
                bucketing). Previously unbounded: a long-running process
                that never drains `durations` (the module-level `metrics`
                singleton is presented as ready-to-use, so this is easy to
                do by accident) would grow one float per `enforce()` call,
                forever (see REL2-5). `None` restores the old, unbounded
                behavior.
        """
        self.counters: dict[str, int] = {}
        self.durations: dict[str, list[float]] = {}
        self.max_observations_per_metric = max_observations_per_metric

    def incr(self, name: str, amount: int = 1) -> None:
        self.counters[name] = self.counters.get(name, 0) + amount

    def observe(self, name: str, value: float) -> None:
        """Record a single observation (e.g. a latency in milliseconds)
        under `name`, for later export as a histogram/summary."""
        bucket = self.durations.setdefault(name, [])
        bucket.append(value)

        if self.max_observations_per_metric is not None:
            while len(bucket) > self.max_observations_per_metric:
                bucket.pop(0)


metrics = Metrics()

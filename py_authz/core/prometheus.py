"""
Optional Prometheus exporter for `Metrics` (REL3-24). Needs the
`prometheus` extra (`pip install 'py-authz[prometheus]'`).

`PrometheusMetrics` is a drop-in `Metrics`: it keeps the in-process
counters and observation buffers (so the control plane's JSON
`/api/v1/metrics` keeps working) and also records each call into a
`prometheus_client` registry, which `render()` serialises in the text
exposition format.

Names are prefixed with `py_authz_`. A counter's name has any `_total`
suffix stripped before registering, since `prometheus_client` appends its
own. Observations become histograms; the bucket boundaries are in
milliseconds, the unit every `observe()` call in this library uses.
"""

import re

from py_authz.core.exceptions import ConfigurationError
from py_authz.core.metrics import Metrics

try:
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Histogram,
        generate_latest,
    )
except ImportError as exc:  # pragma: no cover - exercised only without the extra
    raise ConfigurationError(
        "PrometheusMetrics needs the prometheus extra: pip install 'py-authz[prometheus]'"
    ) from exc

#: Milliseconds: sub-millisecond cache hits up to multi-second timeouts.
DEFAULT_BUCKETS_MS = (0.5, 1, 2.5, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000)

CONTENT_TYPE = CONTENT_TYPE_LATEST

_INVALID = re.compile(r"[^a-zA-Z0-9_]")


class PrometheusMetrics(Metrics):
    def __init__(
        self,
        *,
        registry: CollectorRegistry | None = None,
        namespace: str = "py_authz",
        buckets: tuple[float, ...] = DEFAULT_BUCKETS_MS,
        max_observations_per_metric: int | None = 10_000,
    ):
        """
        Args:
            registry: Where metrics are registered. Defaults to a private
                registry, so two instances (or tests) never collide on
                the global `prometheus_client.REGISTRY`.
            namespace: Prefix for every metric name.
            buckets: Histogram bucket boundaries, in milliseconds.
        """
        super().__init__(max_observations_per_metric=max_observations_per_metric)
        self.registry = registry if registry is not None else CollectorRegistry()
        self.namespace = namespace
        self.buckets = buckets
        self._counters: dict[str, Counter] = {}
        self._histograms: dict[str, Histogram] = {}

    def _metric_name(self, name: str) -> str:
        return _INVALID.sub("_", name)

    def incr(self, name: str, amount: int = 1) -> None:
        super().incr(name, amount)
        counter = self._counters.get(name)
        if counter is None:
            base = self._metric_name(name).removesuffix("_total")
            counter = Counter(
                base, f"py-authz counter {name}", namespace=self.namespace, registry=self.registry
            )
            self._counters[name] = counter
        counter.inc(amount)

    def observe(self, name: str, value: float) -> None:
        super().observe(name, value)
        histogram = self._histograms.get(name)
        if histogram is None:
            histogram = Histogram(
                self._metric_name(name),
                f"py-authz observation {name}",
                namespace=self.namespace,
                registry=self.registry,
                buckets=self.buckets,
            )
            self._histograms[name] = histogram
        histogram.observe(value)

    def render(self) -> bytes:
        """The registry in Prometheus text format (`CONTENT_TYPE`)."""
        return generate_latest(self.registry)

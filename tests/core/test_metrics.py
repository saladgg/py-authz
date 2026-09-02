from py_authz.core.metrics import Metrics, metrics


def test_incr_starts_at_one():
    m = Metrics()
    m.incr("checks")
    assert m.counters == {"checks": 1}


def test_incr_increments_existing_counter():
    m = Metrics()
    m.incr("a")
    m.incr("a")
    m.incr("b")

    assert m.counters == {"a": 2, "b": 1}


def test_module_level_singleton_exists():
    assert isinstance(metrics, Metrics)


def test_observe_records_values_under_name():
    m = Metrics()
    m.observe("latency_ms", 12.5)
    m.observe("latency_ms", 7.0)
    m.observe("other", 1.0)

    assert m.durations == {"latency_ms": [12.5, 7.0], "other": [1.0]}


def test_incr_accepts_custom_amount():
    m = Metrics()
    m.incr("checks", amount=3)
    m.incr("checks", amount=2)

    assert m.counters == {"checks": 5}


# ----------------------------------------------------------------------
# Regression coverage for REL2-5: `durations[name]` used to grow without
# bound — one float per `observe()` call, forever.
# ----------------------------------------------------------------------


def test_observe_caps_observations_per_metric():
    m = Metrics(max_observations_per_metric=3)

    for i in range(10):
        m.observe("latency_ms", float(i))

    # Oldest dropped first — only the most recent `max` observations survive.
    assert m.durations["latency_ms"] == [7.0, 8.0, 9.0]


def test_observe_unbounded_when_max_is_none():
    m = Metrics(max_observations_per_metric=None)

    for i in range(20):
        m.observe("latency_ms", float(i))

    assert len(m.durations["latency_ms"]) == 20

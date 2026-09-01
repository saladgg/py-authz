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

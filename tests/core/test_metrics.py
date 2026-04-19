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

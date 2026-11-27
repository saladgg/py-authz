"""Tests for py_authz.core.prometheus.PrometheusMetrics (REL3-24)."""

from py_authz.core.prometheus import CONTENT_TYPE, PrometheusMetrics


def test_records_into_both_the_json_buffers_and_prometheus():
    m = PrometheusMetrics()

    m.incr("authz_check_total")
    m.incr("authz_check_total", 2)
    m.incr("odd-name.total")
    m.observe("authz_check_duration_ms", 3.0)
    m.observe("authz_check_duration_ms", 700.0)

    assert m.counters["authz_check_total"] == 3
    assert list(m.durations["authz_check_duration_ms"]) == [3.0, 700.0]
    text = m.render().decode()
    assert "py_authz_authz_check_total 3.0" in text
    assert "py_authz_odd_name_total 1.0" in text
    assert 'py_authz_authz_check_duration_ms_bucket{le="5.0"} 1.0' in text
    assert "py_authz_authz_check_duration_ms_count 2.0" in text
    assert CONTENT_TYPE.startswith("text/plain")


def test_instances_use_separate_registries():
    a, b = PrometheusMetrics(), PrometheusMetrics()
    a.incr("x_total")
    b.incr("x_total")  # would raise on a shared registry

    assert "py_authz_x_total 1.0" in b.render().decode()


def test_custom_namespace_and_buckets():
    m = PrometheusMetrics(namespace="cp", buckets=(1.0, 10.0))
    m.observe("lat_ms", 5)

    text = m.render().decode()
    assert 'cp_lat_ms_bucket{le="10.0"} 1.0' in text
    assert 'le="2.5"' not in text

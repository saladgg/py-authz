"""Tests for py_authz.utils.deps — optional-dependency loaders."""

from py_authz.utils import deps


def test_require_postgres_returns_asyncpg():
    import asyncpg

    assert deps.require_postgres() is asyncpg


def test_redis_from_url_applies_timeout_defaults(monkeypatch):
    """REL3-5: redis-py defaults to blocking forever; every client built
    from a URL must get bounded socket/connect timeouts."""
    import redis.asyncio as redis

    captured = {}

    def fake_from_url(url, **kwargs):
        captured["url"] = url
        captured["kwargs"] = kwargs
        return "client"

    monkeypatch.setattr(redis, "from_url", fake_from_url)

    assert deps.redis_from_url("redis://localhost:6379/0") == "client"
    assert captured["url"] == "redis://localhost:6379/0"
    assert captured["kwargs"] == deps.REDIS_CLIENT_DEFAULTS
    assert captured["kwargs"]["socket_timeout"] == deps.REDIS_SOCKET_TIMEOUT


def test_redis_from_url_overrides_win_over_defaults(monkeypatch):
    import redis.asyncio as redis

    captured = {}
    monkeypatch.setattr(redis, "from_url", lambda url, **kw: captured.update(kw))

    deps.redis_from_url("redis://x", socket_timeout=5, decode_responses=True)

    assert captured["socket_timeout"] == 5
    assert captured["decode_responses"] is True
    assert captured["socket_connect_timeout"] == deps.REDIS_CONNECT_TIMEOUT
    assert captured["health_check_interval"] == deps.REDIS_HEALTH_CHECK_INTERVAL

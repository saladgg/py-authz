from py_authz.core.context import get_request_id, set_request_id


def test_set_and_get_request_id():
    set_request_id("req-123")
    assert get_request_id() == "req-123"


def test_request_id_default_none():
    import contextvars

    from py_authz.core import context as ctx_module

    # Run in a fresh context so the default path is exercised.
    contextvars.copy_context()

    def _read_fresh():
        # Unset by creating a new ContextVar lookup
        return ctx_module.request_id_var.get()

    # Ensure some value exists, but confirm default behavior via new context
    fresh_ctx = contextvars.Context()
    assert fresh_ctx.run(_read_fresh) is None

from django_authz.middleware.request_context import RequestContextMiddleware
from django.http import HttpRequest


def test_process_request_sets_context():
    middleware = RequestContextMiddleware(get_response=lambda r: r)
    request = HttpRequest()
    assert middleware.process_request(request) is None
    assert hasattr(request, "context")
    assert "request_id" in request.context

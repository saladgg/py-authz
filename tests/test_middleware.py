from drf2auth.middleware import RequestContextMiddleware
from django.http import HttpRequest

def test_process_request_noop():
    middleware = RequestContextMiddleware(get_response=lambda r: r)
    request = HttpRequest()
    assert middleware.process_request(request) is None

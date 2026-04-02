import pytest
from unittest.mock import MagicMock, patch

from django.core.exceptions import PermissionDenied
from django.http import Http404

from django_authz.authorization.decorators import fga_requires


class SimpleView:
    @fga_requires(object_type="doc", relation="reader")
    def get(self, request, **kwargs):
        return "view-response"


@pytest.fixture
def mock_fga_client():
    """Patch OpenFGAClient in the decorators module and return the mock instance."""
    mock_instance = MagicMock()
    with patch("django_authz.authorization.decorators.OpenFGAClient", return_value=mock_instance):
        yield mock_instance


def test_decorator_raises_http404_when_pk_missing(rf):
    view = SimpleView()
    request = rf.get("/")
    request.user = MagicMock(pk=1)
    with pytest.raises(Http404):
        view.get(request)


def test_decorator_allows_and_calls_view_when_fga_returns_true(rf, mock_fga_client):
    mock_fga_client.check.return_value = True
    view = SimpleView()
    request = rf.get("/")
    request.user = MagicMock(pk=1)

    result = view.get(request, pk="42")

    assert result == "view-response"
    mock_fga_client.check.assert_called_once_with(
        user="user:1", relation="reader", object_="doc:42"
    )


def test_decorator_raises_permission_denied_when_fga_returns_false(rf, mock_fga_client):
    mock_fga_client.check.return_value = False
    view = SimpleView()
    request = rf.get("/")
    request.user = MagicMock(pk=1)

    with pytest.raises(PermissionDenied):
        view.get(request, pk="42")


def test_decorator_uses_custom_user_fmt(rf, mock_fga_client):
    mock_fga_client.check.return_value = True

    class CustomView:
        @fga_requires(
            object_type="project",
            relation="editor",
            object_id_kwarg="project_id",
            user_fmt=lambda req, **kw: "user:custom",
        )
        def post(self, request, **kwargs):
            return "ok"

    view = CustomView()
    request = rf.post("/")
    request.user = MagicMock(pk=99)

    result = view.post(request, project_id="7")

    assert result == "ok"
    mock_fga_client.check.assert_called_once_with(
        user="user:custom", relation="editor", object_="project:7"
    )


def test_decorator_uses_custom_object_id_kwarg(rf, mock_fga_client):
    mock_fga_client.check.return_value = True

    class SlugView:
        @fga_requires(object_type="article", relation="viewer", object_id_kwarg="slug")
        def get(self, request, **kwargs):
            return "ok"

    view = SlugView()
    request = rf.get("/")
    request.user = MagicMock(pk=5)

    view.get(request, slug="my-article")

    mock_fga_client.check.assert_called_once_with(
        user="user:5", relation="viewer", object_="article:my-article"
    )


def test_decorator_raises_http404_for_custom_kwarg_when_missing(rf):
    class SlugView:
        @fga_requires(object_type="article", relation="viewer", object_id_kwarg="slug")
        def get(self, request, **kwargs):
            return "ok"

    view = SlugView()
    request = rf.get("/")
    request.user = MagicMock(pk=5)

    with pytest.raises(Http404):
        view.get(request)

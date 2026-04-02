import pytest
from django.contrib.auth.models import AnonymousUser
from django.core.exceptions import PermissionDenied
from django.views.generic import View

from django_authz.permissions import FGAPermissionMixin
from django_authz.authorization.openfga import OpenFGAClient


class DummyFGA(OpenFGAClient):
    def check(self, user, relation, object_):
        return relation == "reader"


dummy_client = DummyFGA(api_url="http://fake-fga", store_id="test-store")


class DenyFGA(OpenFGAClient):
    def check(self, user, relation, object_):
        return False


deny_client = DenyFGA(api_url="http://fake-fga", store_id="test-store")


class DummyObj:
    pk = 42


def test_fga_permission_mixin_raises_without_client():
    """FGAPermissionMixin.dispatch raises ValueError when fga_client is not set."""
    mixin = FGAPermissionMixin()
    with pytest.raises(ValueError, match="fga_client"):
        mixin.dispatch(None)


def test_fga_permission_mixin_raises_without_relation():
    """FGAPermissionMixin.dispatch raises ValueError when fga_relation is not set."""
    mixin = FGAPermissionMixin()
    mixin.fga_client = dummy_client
    with pytest.raises(ValueError, match="fga_relation"):
        mixin.dispatch(None)


@pytest.mark.django_db
def test_fga_permission_mixin_allows_when_check_returns_true(rf):
    """dispatch proceeds to the view when fga_client.check returns True."""

    class AllowView(FGAPermissionMixin, View):
        fga_client = dummy_client
        fga_relation = "reader"

        def get_object(self):
            return DummyObj()

        def get(self, request, *args, **kwargs):  # noqa: ARG002
            return "allowed"

    request = rf.get("/")
    request.user = AnonymousUser()
    view = AllowView()
    view.request = request
    view.args = ()
    view.kwargs = {}

    response = view.dispatch(request)
    assert response == "allowed"


@pytest.mark.django_db
def test_fga_permission_mixin_denies_when_check_returns_false(rf):
    """dispatch calls handle_no_permission when fga_client.check returns False."""

    class DenyView(FGAPermissionMixin, View):
        fga_client = deny_client
        fga_relation = "writer"
        raise_exception = True

        def get_object(self):
            return DummyObj()

    request = rf.get("/")
    request.user = AnonymousUser()
    view = DenyView()
    view.request = request
    view.args = ()
    view.kwargs = {}

    with pytest.raises(PermissionDenied):
        view.dispatch(request)


def test_fga_permission_mixin_get_fga_user(rf):
    """get_fga_user returns str(request.user)."""
    mixin = FGAPermissionMixin()
    request = rf.get("/")
    request.user = AnonymousUser()
    mixin.request = request
    assert mixin.get_fga_user() == str(request.user)

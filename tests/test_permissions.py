import pytest
from django_authz.permissions import FGAPermissionMixin
from django_authz.authorization.openfga import OpenFGAClient


class DummyFGA(OpenFGAClient):
    def check(self, _user, relation, _object):
        return relation == "reader"


dummy_client = DummyFGA(api_url="http://fake-fga", store_id="test-store")


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

from rest_framework.test import APIRequestFactory
from drf2auth.permissions.drf_permissions import FGAPermission
from drf2auth.authorization.openfga import OpenFGAClient

class DummyFGA(OpenFGAClient):
    def check(self, user, relation, object_):
        return relation == "reader"

class IsReader(FGAPermission):
    client = DummyFGA(api_url="http://fake-fga", store_id="test-store")
    relation = "reader"

def test_permission_granted():
    factory = APIRequestFactory()
    request = factory.get("/")
    request.user = "user:alice"

    perm = IsReader()
    assert perm.has_permission(request, None)

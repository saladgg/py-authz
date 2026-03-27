import pytest
from django_authz.authorization.openfga import OpenFGAClient


class DummyFGA(OpenFGAClient):
    def check(self, _user, relation, object_):
        return relation == "reader" and object_ == "doc:1"


@pytest.fixture
def fga():
    return DummyFGA(api_url="http://fake-fga", store_id="test-store")


def test_reader_allowed(fga):
    assert fga.check("user:alice", "reader", "doc:1")


def test_editor_denied(fga):
    assert not fga.check("user:alice", "editor", "doc:1")

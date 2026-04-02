import pytest
from django_authz.authorization.openfga import OpenFGAClient


class DummyFGA(OpenFGAClient):
    def check(self, user, relation, object_):
        return relation == "reader" and object_ == "doc:1"


@pytest.fixture
def fga():
    return DummyFGA(api_url="http://fake-fga", store_id="test-store")


def test_reader_allowed(fga):
    assert fga.check("user:alice", "reader", "doc:1")


def test_editor_denied(fga):
    assert not fga.check("user:alice", "editor", "doc:1")


# ---------------------------------------------------------------------------
# OpenFGAClient REST paths (mocked HTTP)
# ---------------------------------------------------------------------------


@pytest.fixture
def rest_client():
    return OpenFGAClient(api_url="http://fga.example.com", store_id="store-1")


def test_rest_client_check_returns_true_when_allowed(rest_client, mock_openfga_http):
    mock_openfga_http["allowed"] = True
    assert rest_client.check("user:alice", "reader", "doc:1") is True


def test_rest_client_check_returns_false_when_denied(rest_client, mock_openfga_http):
    mock_openfga_http["allowed"] = False
    assert rest_client.check("user:alice", "editor", "doc:1") is False


def test_rest_client_check_sends_correct_payload(rest_client, mock_openfga_http):
    rest_client.check("user:alice", "reader", "doc:42")
    mock_openfga_http["post"].assert_called_once()
    _, kwargs = mock_openfga_http["post"].call_args
    payload = kwargs["json"]
    assert payload["tuple_key"]["user"] == "user:alice"
    assert payload["tuple_key"]["relation"] == "reader"
    assert payload["tuple_key"]["object"] == "doc:42"


def test_rest_client_write_posts_to_correct_endpoint(rest_client, mock_openfga_http):
    tuples = [{"user": "user:alice", "relation": "reader", "object": "doc:1"}]
    rest_client.write(tuples)
    mock_openfga_http["post"].assert_called_once()
    url = mock_openfga_http["post"].call_args[0][0]
    assert url.endswith("/write")


def test_rest_client_list_relations_returns_list(rest_client, mock_openfga_http):
    mock_openfga_http["relations"] = ["reader", "editor"]
    result = rest_client.list_relations("user:alice", "doc:1")
    assert result == ["reader", "editor"]


def test_rest_client_list_relations_returns_empty_list(rest_client, mock_openfga_http):
    mock_openfga_http["relations"] = []
    result = rest_client.list_relations("user:alice", "doc:1")
    assert result == []

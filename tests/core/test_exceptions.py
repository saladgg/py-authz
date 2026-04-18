from py_authz.core.exceptions import ExternalServiceError


def test_external_error():
    try:
        raise ExternalServiceError("Failure", service="openfga")
    except ExternalServiceError as e:
        assert e.service == "openfga"

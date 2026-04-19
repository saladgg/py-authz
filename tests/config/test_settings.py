from py_authz.config.settings import Settings


def test_settings_has_sensible_default_openfga_url():
    s = Settings()
    assert s.openfga_url == "http://localhost:8080"


def test_settings_override_openfga_url():
    s = Settings(openfga_url="http://custom:9090")
    assert s.openfga_url == "http://custom:9090"

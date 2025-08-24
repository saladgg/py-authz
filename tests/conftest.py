import pytest
from django.conf import settings

@pytest.fixture(autouse=True, scope="session")
def configure_settings():
    """Minimal Django settings for pytest-django."""
    settings.configure(
        DEBUG=True,
        SECRET_KEY="test-key",
        ALLOWED_HOSTS=["*"],
        ROOT_URLCONF="tests.urls",
        INSTALLED_APPS=[
            "django.contrib.auth",
            "django.contrib.contenttypes",
            "rest_framework",
            "drf_authz",
        ],
        MIDDLEWARE=["drf_authz.middleware.RequestContextMiddleware"],
    )
    yield

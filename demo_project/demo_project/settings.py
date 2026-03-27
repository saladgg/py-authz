"""Django settings for the django-authz demo project.

This is for local development and demonstration only. Do NOT use these
settings (especially SECRET_KEY, DEBUG=True) in production.

Quick-start: set real values via environment variables prefixed with
DJANGO_AUTHZ_ (e.g. DJANGO_AUTHZ_OPENFGA_API_URL).
"""

from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
SECRET_KEY = "django-insecure-demo"
DEBUG = True
ALLOWED_HOSTS = ["*"]

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "rest_framework",
    "django_authz",
    "api",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
    # Ensures request.user, request.context, and request.request_id are always set.
    "django_authz.middleware.request_context.RequestContextMiddleware",
]

ROOT_URLCONF = "demo_project.urls"

TEMPLATES = [{
    "BACKEND": "django.template.backends.django.DjangoTemplates",
    "DIRS": [],
    "APP_DIRS": True,
    "OPTIONS": {"context_processors": [
        "django.template.context_processors.debug",
        "django.template.context_processors.request",
        "django.contrib.auth.context_processors.auth",
        "django.contrib.messages.context_processors.messages",
    ]},
}]

WSGI_APPLICATION = "demo_project.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

STATIC_URL = "static/"

# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

# JWTAuthenticationBackend is a standard Django auth backend.
# It decodes Bearer tokens and populates request.jwt_principal.
AUTHENTICATION_BACKENDS = [
    "django_authz.authentication.jwt.JWTAuthenticationBackend",
    "django.contrib.auth.backends.ModelBackend",  # fallback for admin/session
]

# ---------------------------------------------------------------------------
# Django REST Framework
# ---------------------------------------------------------------------------

REST_FRAMEWORK = {
    # DRF uses its own auth pipeline. By default it checks SessionAuthentication
    # and BasicAuthentication. For production JWT-only APIs, implement a custom
    # DRF BaseAuthentication subclass that calls JWTAuthenticationBackend.
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "rest_framework.authentication.SessionAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

# ---------------------------------------------------------------------------
# django-authz
# ---------------------------------------------------------------------------

DJANGO_AUTHZ = {
    # Override with real values in production via environment variables:
    #   DJANGO_AUTHZ_KEYCLOAK_URL, DJANGO_AUTHZ_KEYCLOAK_REALM, etc.
    "VERIFY_JWT": False,  # disable signature verification in local dev
    "KEYCLOAK_URL": "https://keycloak.example.com",
    "KEYCLOAK_REALM": "myrealm",
    "KEYCLOAK_CLIENT_ID": "backend",
    "KEYCLOAK_CLIENT_SECRET": "***",
    "OPENFGA_API_URL": "http://localhost:8080",
    "OPENFGA_STORE_ID": "01H...",
}

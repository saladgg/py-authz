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
    "drf-authz",
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
    "drf-authz.middleware.request_context.RequestContextMiddleware", # Add to middleware
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

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": BASE_DIR / "db.sqlite3"}}

STATIC_URL = "static/"

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "drf-authz.authentication.jwt.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

DRF-AUTHz = {
    # Override via env in real deployments
    "KEYCLOAK_URL": "https://keycloak.example.com",
    "KEYCLOAK_REALM": "myrealm",
    "KEYCLOAK_CLIENT_ID": "backend",
    "KEYCLOAK_CLIENT_SECRET": "***",
    "OPENFGA_API_URL": "https://api.openfga.example.com",
    "OPENFGA_STORE_ID": "01H...",
}


## ======================================================
## Clean-up based on
## ======================================================

# Django settings.py

INSTALLED_APPS = [
    ...
    "rest_framework",
    "drf-authz",  # our library
]

REST_FRAMEWORK = {
    "DEFAULT_AUTHENTICATION_CLASSES": [
        "drf-authz.authentication.jwt.JWTAuthentication",
    ],
    "DEFAULT_PERMISSION_CLASSES": [
        "rest_framework.permissions.IsAuthenticated",
    ],
}

# Example DRF2Auth settings (optional)
DRF2AUTH = {
    "AUTHZ_BACKEND": "rest",  # or "sdk"
    "OPENFGA_API_URL": "http://localhost:8080",
    "OPENFGA_STORE_ID": "store123",
    "OIDC_ISSUER": "https://keycloak.example.com/realms/myrealm",
    "OIDC_AUDIENCE": "my-backend-client",
}

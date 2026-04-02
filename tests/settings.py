SECRET_KEY = "test-key"
DEBUG = True
ALLOWED_HOSTS = ["*"]
INSTALLED_APPS = [
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django_authz",
]
MIDDLEWARE = ["django_authz.middleware.request_context.RequestContextMiddleware"]
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": ":memory:",
    }
}
DJANGO_AUTHZ = {
    "VERIFY_JWT": False,
}

# Minimal stubs required by mozilla-django-oidc's __init__
OIDC_RP_CLIENT_ID = "test-client"
OIDC_RP_CLIENT_SECRET = "test-secret"
OIDC_OP_TOKEN_ENDPOINT = "https://example.com/token"
OIDC_OP_USER_ENDPOINT = "https://example.com/userinfo"
OIDC_OP_JWKS_ENDPOINT = "https://example.com/jwks"
OIDC_RP_SIGN_ALGO = "RS256"

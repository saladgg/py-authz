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

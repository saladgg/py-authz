"""AppConfig for django-authz.

Add ``"django_authz"`` to ``INSTALLED_APPS`` to register this config.
"""

from django.apps import AppConfig


class DjangoAuthzConfig(AppConfig):
    """Django application configuration for django-authz."""

    default_auto_field = "django.db.models.BigAutoField"
    name = "django_authz"
    verbose_name = "django-authz: Keycloak + OpenFGA for Django"

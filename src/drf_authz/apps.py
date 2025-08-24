from django.apps import AppConfig


class DrfAuthzConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "drf_authz"
    verbose_name = "DrfAuthz: Keycloak + OpenFGA for DRF"
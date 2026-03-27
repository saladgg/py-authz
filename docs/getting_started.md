# Getting Started

1. Install `django-authz`:

   ```bash
   pip install django-authz
   ```

2. Add to `INSTALLED_APPS` and middleware:

   ```python
   INSTALLED_APPS += ["django_authz"]
   MIDDLEWARE += ["django_authz.middleware.request_context.RequestContextMiddleware"]
   ```

3. Configure Keycloak & OpenFGA settings (see [Configuration](configuration.md)).

4. Register an authentication backend:

   ```python
   AUTHENTICATION_BACKENDS = [
       "django_authz.authentication.jwt.JWTAuthenticationBackend",
       "django.contrib.auth.backends.ModelBackend",
   ]
   ```

5. Apply `FGAPermissionMixin` to class-based detail views or `@fga_requires` to method-based views.

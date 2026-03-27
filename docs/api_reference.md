# API Reference

## Authentication

- `django_authz.authentication.jwt.JWTAuthenticationBackend`
  — Django authentication backend; decodes Bearer JWTs and provisions users.
- `django_authz.authentication.oidc.OIDCAuthenticationBackend`
  — OIDC backend extending `mozilla-django-oidc`.
- `django_authz.authentication.keycloak.KeycloakAdmin`
  — Thin wrapper around `python-keycloak` admin for management tasks.
- `django_authz.authentication.backends.get_or_create_user`
  — Default user-provisioning helper; override via subclassing or signals.

## Authorization

- `django_authz.authorization.base.BaseOpenFGAClient`
  — Abstract base class defining the common client interface.
- `django_authz.authorization.openfga.OpenFGAClient`
  — Lightweight REST client using `requests`.
- `django_authz.authorization.openfga_sdk.OpenFGASDKClient`
  — SDK-based async client wrapping `openfga-sdk`.
- `django_authz.authorization.decorators.fga_requires`
  — Decorator for method-based views enforcing an FGA relation check.
- `django_authz.authorization.policies.Policy`
  — High-level policy helper; wraps `OpenFGAClient.check()`.

## Permissions

- `django_authz.permissions.FGAPermissionMixin`
  — CBV mixin; calls `get_object()` then checks the FGA relation before dispatch.

## Middleware

- `django_authz.middleware.request_context.RequestContextMiddleware`
  — Ensures `request.user` and `request.context` (with `request_id`) always exist.

## Models

- `django_authz.models.tokens.Principal` — Decoded JWT principal (subject, email, claims).
- `django_authz.models.tokens.IDToken` — Keycloak ID token dataclass.
- `django_authz.models.tokens.AccessToken` — Raw access token dataclass.
- `django_authz.models.relations.RelationTuple` — FGA relation tuple dataclass.

## Management Commands

- `python manage.py sync_openfga` — Sync predefined policy tuples into OpenFGA.

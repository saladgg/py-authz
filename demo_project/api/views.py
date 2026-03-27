"""Demo API views for the django-authz demo project.

These views demonstrate how to use django-authz's authentication and
authorization primitives in real Django REST Framework views.

Endpoints
---------
- ``GET /whoami/``   — Returns the authenticated user's identity.
- ``GET /docs/<doc_id>/``   — Requires the ``reader`` FGA relation on the document.
- ``POST /docs/<doc_id>/edit/`` — Requires the ``editor`` FGA relation on the document.
"""

from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.views import APIView

from django_authz.authorization.decorators import fga_requires


class WhoAmIView(APIView):
    """Return identity information for the currently authenticated user.

    The response includes the Django user fields as well as the decoded JWT
    principal (``request.jwt_principal``) when a Bearer token was presented.
    No FGA check is performed — authentication alone is sufficient.

    Example response::

        {
            "id": 1,
            "username": "alice",
            "email": "alice@example.com",
            "subject": "keycloak-uuid-here"
        }
    """

    def get(self, request: Request) -> Response:
        principal = getattr(request, "jwt_principal", None)
        return Response({
            "id": getattr(request.user, "pk", None),
            "username": getattr(request.user, "username", None),
            "email": getattr(request.user, "email", None),
            # Populated by JWTAuthenticationBackend from the JWT 'sub' claim.
            "subject": principal.subject if principal else None,
        })


class DocumentView(APIView):
    """Retrieve a document by ID.

    Requires the calling user to hold the ``reader`` relation on the requested
    document in OpenFGA (checked via ``@fga_requires``).

    URL parameter
    -------------
    doc_id : str
        The document identifier (used as the FGA object ID).
    """

    @fga_requires(object_type="doc", relation="reader", object_id_kwarg="doc_id")
    def get(self, request: Request, doc_id: str) -> Response:
        return Response({"doc_id": doc_id, "content": "Hello World"})


class DocumentEditView(APIView):
    """Edit a document by ID.

    Requires the calling user to hold the ``editor`` relation on the requested
    document in OpenFGA (checked via ``@fga_requires``).

    URL parameter
    -------------
    doc_id : str
        The document identifier (used as the FGA object ID).
    """

    @fga_requires(object_type="doc", relation="editor", object_id_kwarg="doc_id")
    def post(self, request: Request, doc_id: str) -> Response:
        return Response({"doc_id": doc_id, "status": "edited"})

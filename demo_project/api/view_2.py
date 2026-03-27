"""Example: Function-based views with the @fga_requires decorator.

This file shows an alternative pattern to ``view_1.py``: using the
``@fga_requires`` decorator directly on a CBV method instead of listing
a permission class.

``@fga_requires`` reads the object ID from the URL kwargs, builds the FGA
tuple (``user:{request.user.pk}``), and raises ``PermissionDenied`` if the
relation check fails. The OpenFGA client is configured from DJANGO_AUTHZ
settings automatically.
"""

from rest_framework.response import Response
from rest_framework.views import APIView

from django_authz.authorization.decorators import fga_requires


class DocumentView(APIView):
    """Retrieve a document. Requires the ``reader`` FGA relation on ``doc:<doc_id>``."""

    @fga_requires(object_type="doc", relation="reader", object_id_kwarg="doc_id")
    def get(self, request, doc_id):
        return Response({"doc_id": doc_id, "content": "Hello World"})


class DocumentEditView(APIView):
    """Edit a document. Requires the ``editor`` FGA relation on ``doc:<doc_id>``."""

    @fga_requires(object_type="doc", relation="editor", object_id_kwarg="doc_id")
    def post(self, request, doc_id):
        return Response({"doc_id": doc_id, "status": "edited"})

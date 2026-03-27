"""Example: Class-based views with FGA permission classes.

This file shows how to use the ``FGAPermission`` base class from
``api.permissions`` to gate DRF views by an OpenFGA relation check.

See ``api/permissions.py`` for how ``IsDocumentReader`` and
``IsDocumentEditor`` are defined.
"""

from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsDocumentEditor, IsDocumentReader


class DocumentView(APIView):
    """Retrieve a document. Requires the ``reader`` FGA relation."""

    permission_classes = [IsDocumentReader]

    def get(self, request, doc_id):
        return Response({"doc_id": doc_id, "content": "Hello World"})


class DocumentEditView(APIView):
    """Edit a document. Requires the ``editor`` FGA relation."""

    permission_classes = [IsDocumentEditor]

    def post(self, request, doc_id):
        return Response({"doc_id": doc_id, "status": "edited"})

from rest_framework.decorators import api_view
from rest_framework.response import Response
from drf2auth.decorators import fga_requires
from drf2auth.authorization.openfga import OpenFGAClient

# Initialize FGA client
fga_client = OpenFGAClient(
    api_url="http://localhost:8080",
    store_id="store123",
)

@api_view(["GET"])
@fga_requires(client=fga_client, relation="reader")
def get_document(request, doc_id):
    """Example: Only 'reader' relation can access this endpoint."""
    return Response({"doc_id": doc_id, "content": "Hello World"})


@api_view(["POST"])
@fga_requires(client=fga_client, relation="editor")
def edit_document(request, doc_id):
    """Example: Only 'editor' relation can edit documents."""
    return Response({"doc_id": doc_id, "status": "edited"})

from drf2auth.permissions import FGAPermission
from drf2auth.authorization.openfga import OpenFGAClient
# from drf2auth.authorization.openfga_sdk import OpenFGASDKClient  # alternative

# Initialize once (singleton style)
fga_client = OpenFGAClient(
    api_url="http://localhost:8080",
    store_id="store123",
)

class IsDocumentReader(FGAPermission):
    client = fga_client
    relation = "reader"

class IsDocumentEditor(FGAPermission):
    client = fga_client
    relation = "editor"

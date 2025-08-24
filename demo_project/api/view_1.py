# from rest_framework.response import Response
# from rest_framework.views import APIView
# from drf-authz.permissions.drf_permissions import FgaPermission


# class WhoAmIView(APIView):
#     permission_classes = [FgaPermission]
#     fga_object_relation = ("project", "viewer")  # demo; normally dynamic per object

#     def get(self, request):
#         user = request.user
#         return Response({
#             "id": getattr(user, "pk", None),
#             "username": getattr(user, "username", None),
#             "email": getattr(user, "email", None),
#         })
        
from rest_framework.views import APIView
from rest_framework.response import Response
from myapp.permissions import IsDocumentReader, IsDocumentEditor

class DocumentView(APIView):
    permission_classes = [IsDocumentReader]

    def get(self, request, doc_id):
        return Response({"doc_id": doc_id, "content": "Hello World"})

class DocumentEditView(APIView):
    permission_classes = [IsDocumentEditor]

    def post(self, request, doc_id):
        return Response({"doc_id": doc_id, "status": "edited"})

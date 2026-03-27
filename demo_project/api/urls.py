"""URL configuration for the demo ``api`` app."""

from django.urls import path

from .views import DocumentEditView, DocumentView, WhoAmIView

urlpatterns = [
    path("whoami/", WhoAmIView.as_view(), name="whoami"),
    path("docs/<str:doc_id>/", DocumentView.as_view(), name="document-detail"),
    path("docs/<str:doc_id>/edit/", DocumentEditView.as_view(), name="document-edit"),
]

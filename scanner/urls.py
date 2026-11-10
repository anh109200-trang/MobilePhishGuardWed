from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("api/scan/", views.api_scan, name="api_scan"),
    path("api/qr/", views.api_qr, name="api_qr"),
]

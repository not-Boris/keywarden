from django.urls import path

from . import views

app_name = "servers"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("<int:server_id>/", views.detail, name="detail"),
]

from django.urls import path

from . import views

app_name = "servers"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("<int:server_id>/", views.detail, name="detail"),
    path("<int:server_id>/audit/", views.audit, name="audit"),
    path("<int:server_id>/shell/", views.shell, name="shell"),
    path("<int:server_id>/settings/", views.settings, name="settings"),
]

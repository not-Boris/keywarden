from django.urls import path

from . import views

app_name = "servers"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("admin/", views.admin_dashboard, name="admin_dashboard"),
    path("<int:server_id>/request-access/", views.request_access, name="request_access"),
    path(
        "access-requests/<int:request_id>/decision/",
        views.decide_access_request,
        name="decide_access_request",
    ),
    path("<int:server_id>/admin/", views.server_admin, name="server_admin"),
    path("<int:server_id>/", views.detail, name="detail"),
    path("<int:server_id>/audit/", views.audit, name="audit"),
    path("<int:server_id>/audit/panel/", views.audit_panel, name="audit_panel"),
    path("<int:server_id>/shell/", views.shell, name="shell"),
    path("<int:server_id>/settings/", views.settings, name="settings"),
]

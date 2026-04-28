from django.urls import path

from . import views

app_name = "servers"

urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("admin/", views.admin_dashboard, name="admin_dashboard"),
    path("admin/users/<int:user_id>/password-reset/", views.admin_send_password_reset, name="admin_send_password_reset"),
    path("admin/users/<int:user_id>/delete/", views.admin_delete_user, name="admin_delete_user"),
    path("admin/servers/<int:server_id>/delete/", views.admin_delete_server, name="admin_delete_server"),
    path("admin/grants/<int:grant_id>/revoke/", views.admin_revoke_grant, name="admin_revoke_grant"),
    path("admin/grants/<int:grant_id>/expiry/", views.admin_change_grant_expiry, name="admin_change_grant_expiry"),
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

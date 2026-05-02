from __future__ import annotations

from django.contrib.admin.sites import AdminSite
from django.contrib.auth import get_user_model
from django.test import RequestFactory, TestCase, override_settings
from django.utils import timezone

from apps.access.models import AccessRequest
from apps.servers.admin import ServerAdmin
from apps.servers.models import Server, ServerAccount, ServerAuditLog, ServerLogSource


class ServerAdminDeleteTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.superuser = User.objects.create_superuser(
            username="admin-delete",
            email="admin-delete@example.com",
            password="pass12345",
        )
        self.user = User.objects.create_user(
            username="member-delete",
            email="member-delete@example.com",
            password="pass12345",
        )
        self.site = AdminSite()
        self.model_admin = ServerAdmin(Server, self.site)
        self.factory = RequestFactory()

    def _request(self):
        request = self.factory.post("/admin/servers/server/")
        request.user = self.superuser
        return request

    @override_settings(KEYWARDEN_ADMIN_DELETE_PREVIEW_MAX_ITEMS=2)
    def test_get_deleted_objects_summarizes_large_cascade(self) -> None:
        server = Server.objects.create(display_name="srv-admin-delete")
        ServerAuditLog.objects.bulk_create(
            [
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="login",
                ),
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="logout",
                ),
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="sudo",
                ),
            ]
        )
        ServerAccount.objects.create(server=server, user=self.user, system_username="member_delete")
        ServerLogSource.objects.create(server=server, kind=ServerLogSource.Kind.JOURNAL, name="system-journal")
        AccessRequest.objects.create(requester=self.user, server=server, request_shell=True)

        deleted_objects, model_count, perms_needed, protected = self.model_admin.get_deleted_objects(
            Server.objects.filter(id=server.id),
            self._request(),
        )

        self.assertEqual(perms_needed, set())
        self.assertEqual(protected, [])
        self.assertIn("Large cascade detected", " ".join(str(item) for item in deleted_objects))
        self.assertEqual(model_count[Server._meta.verbose_name_plural], 1)
        self.assertEqual(model_count[ServerAuditLog._meta.verbose_name_plural], 3)
        self.assertEqual(model_count[ServerAccount._meta.verbose_name_plural], 1)
        self.assertEqual(model_count[ServerLogSource._meta.verbose_name_plural], 1)
        self.assertEqual(model_count[AccessRequest._meta.verbose_name_plural], 1)

    @override_settings(KEYWARDEN_ADMIN_DELETE_PREVIEW_MAX_ITEMS=2)
    def test_get_deleted_objects_accepts_plain_object_list(self) -> None:
        server = Server.objects.create(display_name="srv-admin-delete-list")
        ServerAuditLog.objects.bulk_create(
            [
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="login",
                ),
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="logout",
                ),
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="sudo",
                ),
            ]
        )

        deleted_objects, model_count, perms_needed, protected = self.model_admin.get_deleted_objects(
            [server],
            self._request(),
        )

        self.assertEqual(perms_needed, set())
        self.assertEqual(protected, [])
        self.assertIn("Large cascade detected", " ".join(str(item) for item in deleted_objects))
        self.assertEqual(model_count[Server._meta.verbose_name_plural], 1)
        self.assertEqual(model_count[ServerAuditLog._meta.verbose_name_plural], 3)

    def test_delete_queryset_prepurges_audit_logs(self) -> None:
        server = Server.objects.create(display_name="srv-admin-delete-purge")
        ServerAuditLog.objects.bulk_create(
            [
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="login",
                ),
                ServerAuditLog(
                    server=server,
                    event_at=timezone.now(),
                    category="auth",
                    event_type="logout",
                ),
            ]
        )

        self.model_admin.delete_queryset(self._request(), Server.objects.filter(id=server.id))

        self.assertFalse(Server.objects.filter(id=server.id).exists())
        self.assertFalse(ServerAuditLog.objects.filter(server_id=server.id).exists())

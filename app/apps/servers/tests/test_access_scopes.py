from __future__ import annotations

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.urls import reverse
from guardian.shortcuts import assign_perm

from apps.access.models import AccessRequest
from apps.servers.models import Server, ServerAccount
from apps.servers.permissions import user_can_logs, user_can_shell, user_can_users, user_has_any_access


class ServerAccessScopeTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="alice",
            email="alice@example.com",
            password="pass12345",
        )
        self.admin = User.objects.create_superuser(
            username="admin",
            email="admin@example.com",
            password="pass12345",
        )
        self.server = Server.objects.create(
            display_name="db-01",
            hostname="db-01.example.test",
        )

    def _grant_perm(self, user, app_label: str, codename: str) -> None:
        perm = Permission.objects.get(
            content_type__app_label=app_label,
            codename=codename,
        )
        user.user_permissions.add(perm)

    def _create_access_request(self, **kwargs) -> AccessRequest:
        payload = {
            "requester": self.user,
            "server": self.server,
            "status": AccessRequest.Status.APPROVED,
            "request_shell": False,
            "request_logs": False,
            "request_users": False,
        }
        payload.update(kwargs)
        return AccessRequest.objects.create(**payload)

    def test_scope_helpers_enforce_request_flags(self) -> None:
        self._create_access_request(request_shell=True, request_logs=False, request_users=False)

        self.assertTrue(user_can_shell(self.user, self.server))
        self.assertFalse(user_can_logs(self.user, self.server))
        self.assertFalse(user_can_users(self.user, self.server))
        self.assertTrue(user_has_any_access(self.user, self.server))

    def test_approved_request_without_scopes_does_not_grant_server_view(self) -> None:
        self._create_access_request(request_shell=False, request_logs=False, request_users=False)

        self.assertFalse(user_has_any_access(self.user, self.server))
        self.assertFalse(self.user.has_perm("servers.view_server", self.server))

    def test_manual_view_perm_allows_logs_and_users_without_access_request(self) -> None:
        assign_perm("view_server", self.user, self.server)

        self.assertTrue(user_can_logs(self.user, self.server))
        self.assertTrue(user_can_users(self.user, self.server))

    def test_audit_view_denied_when_logs_scope_not_granted(self) -> None:
        self._create_access_request(request_users=True, request_logs=False)
        self.client.login(username="alice", password="pass12345")

        response = self.client.get(reverse("servers:audit", args=[self.server.id]))

        self.assertEqual(response.status_code, 404)

    def test_detail_view_denied_when_users_scope_not_granted(self) -> None:
        self._create_access_request(request_logs=True, request_users=False)
        self.client.login(username="alice", password="pass12345")

        response = self.client.get(reverse("servers:detail", args=[self.server.id]))

        self.assertEqual(response.status_code, 404)

    def test_dashboard_request_access_creates_pending_request(self) -> None:
        self._grant_perm(self.user, "access", "add_accessrequest")
        self.client.login(username="alice", password="pass12345")

        response = self.client.post(reverse("servers:request_access", args=[self.server.id]))

        self.assertEqual(response.status_code, 302)
        self.assertTrue(
            AccessRequest.objects.filter(
                requester=self.user,
                server=self.server,
                status=AccessRequest.Status.PENDING,
                request_shell=True,
                request_logs=True,
                request_users=True,
            ).exists()
        )

    def test_admin_can_approve_pending_request(self) -> None:
        pending = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.PENDING,
            request_shell=True,
            request_logs=True,
            request_users=True,
        )
        self.client.login(username="admin", password="pass12345")

        response = self.client.post(
            reverse("servers:decide_access_request", args=[pending.id]),
            {"action": "approve"},
        )

        self.assertEqual(response.status_code, 302)
        pending.refresh_from_db()
        self.assertEqual(pending.status, AccessRequest.Status.APPROVED)
        self.assertEqual(pending.decided_by_id, self.admin.id)

    def test_admin_dashboard_requires_admin(self) -> None:
        self.client.login(username="alice", password="pass12345")
        response = self.client.get(reverse("servers:admin_dashboard"))
        self.assertEqual(response.status_code, 404)

    def test_admin_dashboard_lists_pending_requests(self) -> None:
        pending = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.PENDING,
            request_shell=True,
        )
        self.client.login(username="admin", password="pass12345")
        response = self.client.get(reverse("servers:admin_dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, pending.requester.username)
        self.assertContains(response, "Access request queue")

    def test_server_admin_requires_admin(self) -> None:
        assign_perm("view_server", self.user, self.server)
        self.client.login(username="alice", password="pass12345")
        response = self.client.get(reverse("servers:server_admin", args=[self.server.id]))
        self.assertEqual(response.status_code, 404)

    def test_server_admin_lists_users_and_server_accounts(self) -> None:
        AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.APPROVED,
            request_shell=True,
            request_logs=True,
            request_users=True,
        )
        ServerAccount.objects.create(
            server=self.server,
            user=self.user,
            system_username="alice_1",
            is_present=True,
        )
        self.client.login(username="admin", password="pass12345")
        response = self.client.get(reverse("servers:server_admin", args=[self.server.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Users with access")
        self.assertContains(response, self.user.username)
        self.assertContains(response, "Server accounts")
        self.assertContains(response, "alice_1")

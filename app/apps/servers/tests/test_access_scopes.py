from __future__ import annotations

from datetime import timedelta
from types import SimpleNamespace

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from guardian.shortcuts import assign_perm
from ninja.errors import HttpError

from apps.access.models import AccessRequest
from apps.accounts.models import ErasureRequest
from apps.core import rbac
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
        self.client.force_login(self.user)

        response = self.client.get(reverse("servers:audit", args=[self.server.id]))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("servers:dashboard"))

    def test_detail_view_denied_when_users_scope_not_granted(self) -> None:
        self._create_access_request(request_logs=True, request_users=False)
        self.client.force_login(self.user)

        response = self.client.get(reverse("servers:detail", args=[self.server.id]))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("servers:dashboard"))

    def test_dashboard_request_access_creates_pending_request(self) -> None:
        self._grant_perm(self.user, "access", "add_accessrequest")
        self.client.force_login(self.user)

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

    def test_dashboard_request_access_scoped_options_are_saved(self) -> None:
        self._grant_perm(self.user, "access", "add_accessrequest")
        self.client.force_login(self.user)

        response = self.client.post(
            reverse("servers:request_access", args=[self.server.id]),
            {
                "scoped_request": "1",
                "request_shell": "1",
                "request_logs": "1",
                "requested_duration_hours": "24",
                "requested_server_username": "ubuntu",
                "reason": "Investigate auth failure",
            },
        )

        self.assertEqual(response.status_code, 302)
        access_request = AccessRequest.objects.get(requester=self.user, server=self.server)
        self.assertEqual(access_request.status, AccessRequest.Status.PENDING)
        self.assertTrue(access_request.request_shell)
        self.assertTrue(access_request.request_logs)
        self.assertFalse(access_request.request_users)
        self.assertEqual(access_request.requested_duration_hours, 24)
        self.assertEqual(access_request.requested_server_username, "ubuntu")
        self.assertEqual(access_request.reason, "Investigate auth failure")

    def test_admin_can_approve_pending_request(self) -> None:
        pending = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.PENDING,
            request_shell=True,
            request_logs=True,
            request_users=True,
        )
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:decide_access_request", args=[pending.id]),
            {"action": "approve"},
        )

        self.assertEqual(response.status_code, 302)
        pending.refresh_from_db()
        self.assertEqual(pending.status, AccessRequest.Status.APPROVED)
        self.assertEqual(pending.decided_by_id, self.admin.id)

    def test_admin_approve_uses_requested_duration_for_expiry(self) -> None:
        pending = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.PENDING,
            request_shell=True,
            requested_duration_hours=4,
        )
        self.client.force_login(self.admin)

        decision_started_at = timezone.now()
        response = self.client.post(
            reverse("servers:decide_access_request", args=[pending.id]),
            {"action": "approve"},
        )

        self.assertEqual(response.status_code, 302)
        pending.refresh_from_db()
        self.assertEqual(pending.status, AccessRequest.Status.APPROVED)
        self.assertIsNotNone(pending.expires_at)
        self.assertGreaterEqual(pending.expires_at, decision_started_at + timedelta(hours=3, minutes=59))

    def test_admin_dashboard_requires_admin(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(reverse("servers:admin_dashboard"))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("servers:dashboard"))

    def test_admin_dashboard_lists_pending_requests(self) -> None:
        pending = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.PENDING,
            request_shell=True,
        )
        self.client.force_login(self.admin)
        response = self.client.get(reverse("servers:admin_dashboard"))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, pending.requester.username)
        self.assertContains(response, "Access request queue")

    def test_admin_dashboard_users_view_shows_gdpr_marker(self) -> None:
        ErasureRequest.objects.create(
            user=self.user,
            reason="Please erase my profile data completely.",
            status=ErasureRequest.Status.PENDING,
        )
        self.client.force_login(self.admin)

        response = self.client.get(reverse("servers:admin_dashboard"), {"view": "users"})

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Send reset email")
        self.assertContains(response, "GDPR request")

    def test_admin_delete_user_from_dashboard(self) -> None:
        User = get_user_model()
        victim = User.objects.create_user(
            username="victim",
            email="victim@example.com",
            password="pass12345",
        )
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:admin_delete_user", args=[victim.id]),
            {"next": reverse("servers:admin_dashboard")},
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(User.objects.filter(id=victim.id).exists())

    def test_admin_send_password_reset_from_dashboard(self) -> None:
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:admin_send_password_reset", args=[self.user.id]),
            {"next": reverse("servers:admin_dashboard")},
        )

        self.assertEqual(response.status_code, 302)

    def test_admin_delete_server_from_dashboard(self) -> None:
        server = Server.objects.create(display_name="delete-me", hostname="delete-me.example.test")
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:admin_delete_server", args=[server.id]),
            {"next": reverse("servers:admin_dashboard")},
        )

        self.assertEqual(response.status_code, 302)
        self.assertFalse(Server.objects.filter(id=server.id).exists())

    def test_admin_revoke_grant_from_dashboard(self) -> None:
        grant = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.APPROVED,
            request_shell=True,
            expires_at=timezone.now() + timedelta(days=3),
        )
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:admin_revoke_grant", args=[grant.id]),
            {"next": reverse("servers:admin_dashboard")},
        )

        self.assertEqual(response.status_code, 302)
        grant.refresh_from_db()
        self.assertEqual(grant.status, AccessRequest.Status.REVOKED)
        self.assertEqual(grant.decided_by_id, self.admin.id)
        self.assertIsNotNone(grant.expires_at)

    def test_admin_change_grant_expiry_from_dashboard(self) -> None:
        grant = AccessRequest.objects.create(
            requester=self.user,
            server=self.server,
            status=AccessRequest.Status.APPROVED,
            request_shell=True,
            expires_at=timezone.now() + timedelta(days=1),
        )
        new_expiry = timezone.now() + timedelta(days=9)
        self.client.force_login(self.admin)

        response = self.client.post(
            reverse("servers:admin_change_grant_expiry", args=[grant.id]),
            {
                "expires_at": timezone.localtime(new_expiry).strftime("%Y-%m-%dT%H:%M"),
                "next": reverse("servers:admin_dashboard"),
            },
        )

        self.assertEqual(response.status_code, 302)
        grant.refresh_from_db()
        self.assertIsNotNone(grant.expires_at)
        self.assertGreater(grant.expires_at, timezone.now() + timedelta(days=8))

    def test_server_admin_requires_admin(self) -> None:
        assign_perm("view_server", self.user, self.server)
        self.client.force_login(self.user)
        response = self.client.get(reverse("servers:server_admin", args=[self.server.id]))
        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, reverse("servers:dashboard"))

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
        self.client.force_login(self.admin)
        response = self.client.get(reverse("servers:server_admin", args=[self.server.id]))
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Users with access")
        self.assertContains(response, self.user.username)
        self.assertContains(response, "Server accounts")
        self.assertContains(response, "alice_1")


class ServerApiRouterTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="api-user",
            email="api-user@example.com",
            password="pass12345",
        )
        self.server_allowed = Server.objects.create(display_name="api-allowed", hostname="api-allowed.example.test")
        self.server_denied = Server.objects.create(display_name="api-denied", hostname="api-denied.example.test")
        assign_perm("view_server", self.user, self.server_allowed)

    def test_list_servers_returns_only_object_permitted_servers(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/api/v1/servers/")
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        ids = {item["id"] for item in payload}
        self.assertIn(self.server_allowed.id, ids)
        self.assertNotIn(self.server_denied.id, ids)

    def test_get_server_forbidden_without_object_permission(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(f"/api/v1/servers/{self.server_denied.id}")
        self.assertEqual(response.status_code, 403)

    def test_get_server_not_found(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get("/api/v1/servers/999999")
        self.assertEqual(response.status_code, 404)

    def test_update_server_requires_change_permission(self) -> None:
        self.client.force_login(self.user)
        response = self.client.patch(
            f"/api/v1/servers/{self.server_allowed.id}",
            data={"display_name": "renamed"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 403)

    def test_update_server_validates_display_name(self) -> None:
        perm = Permission.objects.get(content_type__app_label="servers", codename="change_server")
        self.user.user_permissions.add(perm)
        self.client.force_login(self.user)
        with self.assertRaises(TypeError):
            self.client.patch(
                f"/api/v1/servers/{self.server_allowed.id}",
                data={"display_name": "   "},
                content_type="application/json",
            )

    def test_update_server_success(self) -> None:
        perm = Permission.objects.get(content_type__app_label="servers", codename="change_server")
        self.user.user_permissions.add(perm)
        self.client.force_login(self.user)
        response = self.client.patch(
            f"/api/v1/servers/{self.server_allowed.id}",
            data={"display_name": "renamed-server"},
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.server_allowed.refresh_from_db()
        self.assertEqual(self.server_allowed.display_name, "renamed-server")


class CoreRbacTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="rbac-user",
            email="rbac-user@example.com",
            password="pass12345",
        )

    def test_role_normalization_and_assignment(self) -> None:
        self.assertEqual(rbac.normalize_role("ADMIN"), rbac.ROLE_ADMIN)
        self.assertEqual(rbac.set_user_role(self.user, "admin"), rbac.ROLE_ADMIN)
        self.user.save(update_fields=["is_staff", "is_superuser"])
        self.assertEqual(rbac.get_user_role(self.user), rbac.ROLE_ADMIN)
        self.assertTrue(self.user.is_staff)
        self.assertTrue(self.user.is_superuser)

        self.assertEqual(rbac.set_user_role(self.user, "user"), rbac.ROLE_USER)
        self.user.save(update_fields=["is_staff", "is_superuser"])
        self.assertEqual(rbac.get_user_role(self.user), rbac.ROLE_USER)
        self.assertFalse(self.user.is_staff)
        self.assertFalse(self.user.is_superuser)

        with self.assertRaises(ValueError):
            rbac.set_user_role(self.user, "invalid")

    def test_require_auth_and_perms_guards(self) -> None:
        with self.assertRaises(HttpError):
            rbac.require_authenticated(SimpleNamespace(user=None))

        request = SimpleNamespace(user=self.user)
        with self.assertRaises(HttpError):
            rbac.require_perms(request, "servers.change_server")

from __future__ import annotations

import json
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import TestCase
from django.utils import timezone
from guardian.shortcuts import assign_perm
from ninja.errors import HttpError

from apps.keys.models import SSHCertificate, SSHKey
from keywarden.api.routers import keys as keys_router


class KeysRouterHelperTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="keys-helper",
            email="keys-helper@example.com",
            password="pass12345",
        )

    def _create_key(self, *, owner=None, name: str = "helper-key", key_b64: str = "AAAA") -> SSHKey:
        key = SSHKey(user=owner or self.user, name=name)
        key.set_public_key(f"ssh-ed25519 {key_b64} comment")
        key.save()
        return key

    def test_ensure_certificate_raises_when_key_is_revoked(self) -> None:
        key = self._create_key()
        key.is_active = False
        key.save(update_fields=["is_active"])

        with self.assertRaises(HttpError):
            keys_router._ensure_certificate(key, self.user)

    def test_ensure_certificate_issues_when_missing_or_expired(self) -> None:
        key_missing = self._create_key(name="missing")
        key_expired = self._create_key(name="expired", key_b64="AAAB")
        SSHCertificate.objects.create(
            key=key_expired,
            user=self.user,
            certificate="ssh-ed25519-cert-v01 AAAA",
            serial=1001,
            principals=["keys-helper"],
            valid_after=timezone.now() - timedelta(days=2),
            valid_before=timezone.now() - timedelta(days=1),
            is_active=True,
        )
        issued = SimpleNamespace(serial=999, certificate="ssh-ed25519-cert-v01 BBBB")
        with patch("keywarden.api.routers.keys.issue_certificate_for_key", return_value=issued) as mocked_issue:
            self.assertIs(keys_router._ensure_certificate(key_missing, self.user), issued)
            self.assertIs(keys_router._ensure_certificate(key_expired, self.user), issued)
            self.assertEqual(mocked_issue.call_count, 2)

    def test_ensure_certificate_returns_existing_active_cert(self) -> None:
        key = self._create_key()
        cert = SSHCertificate.objects.create(
            key=key,
            user=self.user,
            certificate="ssh-ed25519-cert-v01 AAAA",
            serial=42,
            principals=["keys-helper"],
            valid_after=timezone.now() - timedelta(minutes=5),
            valid_before=timezone.now() + timedelta(days=1),
            is_active=True,
        )

        with patch("keywarden.api.routers.keys.issue_certificate_for_key") as mocked_issue:
            result = keys_router._ensure_certificate(key, self.user)
            self.assertEqual(result.id, cert.id)
            mocked_issue.assert_not_called()


class KeysApiRouterTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="keys-user",
            email="keys-user@example.com",
            password="pass12345",
        )
        self.other_user = User.objects.create_user(
            username="keys-other",
            email="keys-other@example.com",
            password="pass12345",
        )

    def _grant_global_perm(self, user, codename: str) -> None:
        perm = Permission.objects.get(content_type__app_label="keys", codename=codename)
        user.user_permissions.add(perm)

    def _create_key(self, *, owner=None, name: str = "api-key", key_b64: str = "AAAA") -> SSHKey:
        key = SSHKey(user=owner or self.user, name=name)
        key.set_public_key(f"ssh-ed25519 {key_b64} comment")
        key.save()
        return key

    def _dummy_cert(self):
        now = timezone.now()
        return SimpleNamespace(
            serial=1234,
            valid_after=now,
            valid_before=now + timedelta(days=1),
            principals=[self.user.username],
            certificate="ssh-ed25519-cert-v01 AAAATEST",
        )

    def test_list_keys_returns_only_object_permitted_keys(self) -> None:
        visible = self._create_key(owner=self.other_user, name="visible")
        hidden = self._create_key(owner=self.other_user, name="hidden", key_b64="AAAB")
        assign_perm("view_sshkey", self.user, visible)
        self.client.force_login(self.user)

        response = self.client.get("/api/v1/keys/")

        self.assertEqual(response.status_code, 200)
        ids = {item["id"] for item in response.json()}
        self.assertIn(visible.id, ids)
        self.assertNotIn(hidden.id, ids)

    def test_list_keys_honors_global_filter_by_user(self) -> None:
        self._grant_global_perm(self.user, "view_sshkey")
        other_key = self._create_key(owner=self.other_user, name="other", key_b64="AAAC")
        self._create_key(owner=self.user, name="self", key_b64="AAAD")
        self.client.force_login(self.user)

        response = self.client.get(f"/api/v1/keys/?user_id={self.other_user.id}&limit=20&offset=0")

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 1)
        self.assertEqual(payload[0]["id"], other_key.id)

    def test_create_key_requires_add_permission(self) -> None:
        self.client.force_login(self.user)

        response = self.client.post(
            "/api/v1/keys/",
            data=json.dumps({"name": "laptop", "public_key": "ssh-ed25519 AAAA"}),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_create_key_for_self_success(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self.client.force_login(self.user)
        with patch("keywarden.api.routers.keys.issue_certificate_for_key", return_value=self._dummy_cert()) as mocked:
            response = self.client.post(
                "/api/v1/keys/",
                data=json.dumps({"name": "laptop", "public_key": "ssh-ed25519 AAAA"}),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["user_id"], self.user.id)
        self.assertEqual(payload["name"], "laptop")
        self.assertTrue(SSHKey.objects.filter(id=payload["id"]).exists())
        mocked.assert_called_once()

    def test_create_key_for_other_user_requires_admin_view_permission(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self.client.force_login(self.user)

        response = self.client.post(
            "/api/v1/keys/",
            data=json.dumps(
                {"name": "other-user-key", "public_key": "ssh-ed25519 AAAA", "user_id": self.other_user.id}
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 403)

    def test_create_key_for_other_user_with_admin_perms(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self._grant_global_perm(self.user, "view_sshkey")
        self.client.force_login(self.user)
        with patch("keywarden.api.routers.keys.issue_certificate_for_key", return_value=self._dummy_cert()):
            response = self.client.post(
                "/api/v1/keys/",
                data=json.dumps(
                    {"name": "other-user-key", "public_key": "ssh-ed25519 AAAA", "user_id": self.other_user.id}
                ),
                content_type="application/json",
            )

        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(payload["user_id"], self.other_user.id)

    def test_create_key_unknown_user_returns_404(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self._grant_global_perm(self.user, "view_sshkey")
        self.client.force_login(self.user)

        response = self.client.post(
            "/api/v1/keys/",
            data=json.dumps(
                {"name": "other-user-key", "public_key": "ssh-ed25519 AAAA", "user_id": 999999}
            ),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 404)

    def test_create_key_validation_paths_raise_type_error(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self.client.force_login(self.user)

        with self.assertRaises(TypeError):
            self.client.post(
                "/api/v1/keys/",
                data=json.dumps({"name": "   ", "public_key": "ssh-ed25519 AAAA"}),
                content_type="application/json",
            )
        with self.assertRaises(TypeError):
            self.client.post(
                "/api/v1/keys/",
                data=json.dumps({"name": "badkey", "public_key": "not-a-key"}),
                content_type="application/json",
            )

    def test_create_key_duplicate_fingerprint_raises_type_error(self) -> None:
        self._grant_global_perm(self.user, "add_sshkey")
        self.client.force_login(self.user)
        self._create_key(owner=self.user, name="existing")

        with self.assertRaises(TypeError):
            self.client.post(
                "/api/v1/keys/",
                data=json.dumps({"name": "duplicate", "public_key": "ssh-ed25519 AAAA"}),
                content_type="application/json",
            )

    def test_get_key_not_found_and_forbidden(self) -> None:
        self.client.force_login(self.user)
        missing = self.client.get("/api/v1/keys/999999")
        self.assertEqual(missing.status_code, 404)

        key = self._create_key(owner=self.other_user, name="forbidden")
        forbidden = self.client.get(f"/api/v1/keys/{key.id}")
        self.assertEqual(forbidden.status_code, 403)

    def test_get_key_success(self) -> None:
        key = self._create_key(name="visible-key")
        assign_perm("view_sshkey", self.user, key)
        self.client.force_login(self.user)

        response = self.client.get(f"/api/v1/keys/{key.id}")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["id"], key.id)

    def test_issue_certificate_requires_object_permission(self) -> None:
        key = self._create_key(owner=self.other_user, name="cert-forbidden")
        self.client.force_login(self.user)

        forbidden = self.client.post(f"/api/v1/keys/{key.id}/certificate")
        self.assertEqual(forbidden.status_code, 403)

        missing = self.client.post("/api/v1/keys/999999/certificate")
        self.assertEqual(missing.status_code, 404)

    def test_issue_certificate_success(self) -> None:
        key = self._create_key(name="cert-ok")
        assign_perm("view_sshkey", self.user, key)
        self.client.force_login(self.user)
        cert = self._dummy_cert()
        with patch("keywarden.api.routers.keys.issue_certificate_for_key", return_value=cert) as mocked:
            response = self.client.post(f"/api/v1/keys/{key.id}/certificate")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["serial"], cert.serial)
        mocked.assert_called_once_with(key, created_by=self.user)

    def test_download_certificate_and_hash(self) -> None:
        key = self._create_key(name="download")
        assign_perm("view_sshkey", self.user, key)
        self.client.force_login(self.user)
        cert = self._dummy_cert()

        with patch("keywarden.api.routers.keys._ensure_certificate", return_value=cert):
            cert_response = self.client.get(f"/api/v1/keys/{key.id}/certificate")
            hash_response = self.client.get(f"/api/v1/keys/{key.id}/certificate.sha256")

        self.assertEqual(cert_response.status_code, 200)
        self.assertIn("attachment;", cert_response["Content-Disposition"])
        self.assertIn("AAAATEST", cert_response.content.decode("utf-8"))

        self.assertEqual(hash_response.status_code, 200)
        hash_payload = hash_response.content.decode("utf-8")
        self.assertIn("keywarden-", hash_payload)
        self.assertTrue(hash_payload.endswith(".pub\n"))

    def test_download_certificate_requires_permission(self) -> None:
        key = self._create_key(owner=self.other_user, name="download-forbidden")
        self.client.force_login(self.user)

        cert_response = self.client.get(f"/api/v1/keys/{key.id}/certificate")
        hash_response = self.client.get(f"/api/v1/keys/{key.id}/certificate.sha256")

        self.assertEqual(cert_response.status_code, 403)
        self.assertEqual(hash_response.status_code, 403)

    def test_update_key_paths(self) -> None:
        key = self._create_key(owner=self.other_user, name="editable", key_b64="AAAE")
        self.client.force_login(self.user)

        forbidden = self.client.patch(
            f"/api/v1/keys/{key.id}",
            data=json.dumps({"name": "renamed"}),
            content_type="application/json",
        )
        self.assertEqual(forbidden.status_code, 403)

        self._grant_global_perm(self.user, "change_sshkey")
        assign_perm("change_sshkey", self.user, key)

        renamed = self.client.patch(
            f"/api/v1/keys/{key.id}",
            data=json.dumps({"name": "renamed"}),
            content_type="application/json",
        )
        self.assertEqual(renamed.status_code, 200)
        key.refresh_from_db()
        self.assertEqual(key.name, "renamed")

        with patch("keywarden.api.routers.keys.revoke_certificate_for_key") as mocked_revoke:
            revoked = self.client.patch(
                f"/api/v1/keys/{key.id}",
                data=json.dumps({"is_active": False}),
                content_type="application/json",
            )
        self.assertEqual(revoked.status_code, 200)
        key.refresh_from_db()
        self.assertFalse(key.is_active)
        self.assertIsNotNone(key.revoked_at)
        mocked_revoke.assert_called_once_with(key)

        with patch("keywarden.api.routers.keys.issue_certificate_for_key", return_value=self._dummy_cert()) as mocked_issue:
            reactivated = self.client.patch(
                f"/api/v1/keys/{key.id}",
                data=json.dumps({"is_active": True}),
                content_type="application/json",
            )
        self.assertEqual(reactivated.status_code, 200)
        key.refresh_from_db()
        self.assertTrue(key.is_active)
        self.assertIsNone(key.revoked_at)
        mocked_issue.assert_called_once_with(key, created_by=self.user)

        with self.assertRaises(TypeError):
            self.client.patch(
                f"/api/v1/keys/{key.id}",
                data=json.dumps({}),
                content_type="application/json",
            )

        not_found = self.client.patch(
            "/api/v1/keys/999999",
            data=json.dumps({"name": "x"}),
            content_type="application/json",
        )
        self.assertEqual(not_found.status_code, 404)

    def test_delete_key_paths(self) -> None:
        key = self._create_key(owner=self.other_user, name="delete-me", key_b64="AAAF")
        self.client.force_login(self.user)

        forbidden = self.client.delete(f"/api/v1/keys/{key.id}")
        self.assertEqual(forbidden.status_code, 403)

        self._grant_global_perm(self.user, "delete_sshkey")
        assign_perm("delete_sshkey", self.user, key)

        with patch("keywarden.api.routers.keys.revoke_certificate_for_key") as mocked_revoke:
            deleted = self.client.delete(f"/api/v1/keys/{key.id}")
        self.assertEqual(deleted.status_code, 204)
        key.refresh_from_db()
        self.assertFalse(key.is_active)
        self.assertIsNotNone(key.revoked_at)
        mocked_revoke.assert_called_once_with(key)

        second_delete = self.client.delete(f"/api/v1/keys/{key.id}")
        self.assertEqual(second_delete.status_code, 204)

        missing = self.client.delete("/api/v1/keys/999999")
        self.assertEqual(missing.status_code, 404)

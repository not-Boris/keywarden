from __future__ import annotations

import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from urllib.parse import quote
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from guardian.shortcuts import assign_perm
from ninja.errors import HttpError

from apps.access.models import AccessRequest
from apps.keys.models import SSHKey
from apps.keys.models import SSHCertificate, SSHCertificateAuthority, parse_public_key
from apps.servers.models import AgentCertificateAuthority, EnrollmentToken, Server, ServerAuditLog, ServerLogSource
from keywarden.api.routers import agent as agent_router


class AgentLogIngestionTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(display_name="web-01", hostname="web-01.example.test")
        self._configure_agent_mtls(self.server)

    def _configure_agent_mtls(self, server: Server) -> None:
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Keywarden Test Agent CA")])
        now = datetime.utcnow()
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        AgentCertificateAuthority.objects.create(
            name="Agent Test CA",
            cert_pem=ca_pem,
            key_pem=ca_key_pem,
            is_active=True,
        )
        agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        agent_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.example.test")]))
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=90))
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = agent_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        fingerprint = agent_cert.fingerprint(hashes.SHA256()).hex()
        serial = format(agent_cert.serial_number, "x")
        server.agent_cert_fingerprint = fingerprint
        server.agent_cert_serial = serial
        server.save(update_fields=["agent_cert_fingerprint", "agent_cert_serial"])
        self.agent_headers = {
            "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY": "SUCCESS",
            "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe=""),
            "HTTP_X_KEYWARDEN_TLS_CLIENT_FINGERPRINT": fingerprint,
        }

    def test_ingest_logs_persists_events(self) -> None:
        payload = [
            {
                "timestamp": "2026-04-14T10:20:30Z",
                "category": "access",
                "event_type": "ssh.login.success",
                "source_kind": "service",
                "source_name": "sshd.service",
                "priority": "6",
                "username": "alice",
                "source_ip": "203.0.113.10",
                "message": "Accepted publickey for alice from 203.0.113.10",
                "fields": {"_SYSTEMD_UNIT": "sshd.service", "PRIORITY": 6},
            },
            {
                "timestamp": "not-a-time",
                "category": "system",
                "event_type": "system",
                "source_ip": "not-an-ip",
                "message": "fallback timestamp test",
                "fields": {"FOO": "bar"},
            },
        ]

        response = self.client.post(
            f"/api/v1/agent/servers/{self.server.id}/logs",
            data=json.dumps(payload),
            content_type="application/json",
            **self.agent_headers,
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["accepted"], 2)
        self.assertEqual(ServerAuditLog.objects.filter(server=self.server).count(), 2)

        success_log = ServerAuditLog.objects.get(event_type="ssh.login.success")
        self.assertEqual(success_log.category, "access")
        self.assertEqual(success_log.username, "alice")
        self.assertEqual(success_log.source_kind, "service")
        self.assertEqual(success_log.source_name, "sshd.service")
        self.assertEqual(success_log.source_ip, "203.0.113.10")
        self.assertEqual(success_log.fields.get("PRIORITY"), "6")

        fallback_log = ServerAuditLog.objects.get(message="fallback timestamp test")
        self.assertIsNone(fallback_log.source_ip)
        self.assertLess(abs((timezone.now() - fallback_log.event_at).total_seconds()), 10)

    def test_ingest_logs_returns_404_for_unknown_server(self) -> None:
        response = self.client.post(
            "/api/v1/agent/servers/999999/logs",
            data=json.dumps([]),
            content_type="application/json",
            **self.agent_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_ingest_logs_requires_agent_mtls(self) -> None:
        response = self.client.post(
            f"/api/v1/agent/servers/{self.server.id}/logs",
            data=json.dumps([]),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_ingest_logs_rejects_mtls_cert_for_different_server(self) -> None:
        other_server = Server.objects.create(display_name="web-02", hostname="web-02.example.test")
        response = self.client.post(
            f"/api/v1/agent/servers/{other_server.id}/logs",
            data=json.dumps([]),
            content_type="application/json",
            **self.agent_headers,
        )
        self.assertEqual(response.status_code, 403)

    def test_log_config_returns_server_sources(self) -> None:
        ServerLogSource.objects.create(
            server=self.server,
            kind=ServerLogSource.Kind.SERVICE,
            name="OpenSSH",
            service_unit="ssh.service",
            category_override="access",
            event_type_override="ssh",
            enabled=True,
        )
        ServerLogSource.objects.create(
            server=self.server,
            kind=ServerLogSource.Kind.FILE,
            name="Auth File",
            file_path="/var/log/auth.log",
            category_override="auth",
            event_type_override="file.line",
            enabled=True,
        )
        ServerLogSource.objects.create(
            server=self.server,
            kind=ServerLogSource.Kind.JOURNAL,
            name="Kernel Journal",
            parser=ServerLogSource.Parser.NONE,
            include_matches={"_TRANSPORT": ["kernel"]},
            category_override="system",
            event_type_override="kernel",
            enabled=True,
        )
        response = self.client.get(
            f"/api/v1/agent/servers/{self.server.id}/log-config",
            **self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)
        payload = response.json()
        self.assertEqual(len(payload), 3)
        kinds = {item["kind"] for item in payload}
        self.assertEqual(kinds, {"service", "file", "journal"})
        for item in payload:
            self.assertTrue(item["source_id"])
            self.assertIn("parser", item)
            self.assertIn("include_matches", item)
            self.assertIn("exclude_matches", item)

    def test_log_config_returns_empty_when_no_sources(self) -> None:
        response = self.client.get(
            f"/api/v1/agent/servers/{self.server.id}/log-config",
            **self.agent_headers,
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), [])


class ServerAuditViewTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="auditor",
            email="auditor@example.com",
            password="pass12345",
        )
        self.server = Server.objects.create(display_name="db-01", hostname="db-01.example.test")
        assign_perm("view_server", self.user, self.server)

        now = timezone.now()
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=5),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.success",
            username="alice",
            source_ip="203.0.113.10",
            message="Accepted publickey for alice",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=4),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.fail",
            username="bob",
            source_ip="198.51.100.5",
            message="Failed password for bob",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=3),
            source_kind="file",
            source_name="/var/log/auth.log",
            category="network",
            event_type="network",
            message="Interface eth0 changed",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=2),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="203.0.113.10",
            message='192.0.2.40 - - [15/Apr/2026:23:57:44 +0000] "GET /api/v1/agent/servers/6/log-config HTTP/2.0" 200 682 "-"',
            fields={"nginx.status": "200"},
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=1),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="198.51.100.5",
            message='192.0.2.41 - - [15/Apr/2026:23:57:45 +0000] "GET /private HTTP/2.0" 401 245 "-"',
            fields={"nginx.status": "401"},
        )

    def test_audit_view_applies_filters(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("servers:audit", args=[self.server.id]),
            {
                "category": "access",
                "event_type": "ssh.login.success",
                "q": "Accepted",
            },
        )

        self.assertEqual(response.status_code, 200)
        logs = list(response.context["initial_panel"]["logs"])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].event_type, "ssh.login.success")


class AgentRouterHelpersTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="helper",
            email="helper@example.com",
            password="pass12345",
        )
        self.server = Server.objects.create(display_name="helper-01", hostname="helper-01.example.test")
        assign_perm("view_server", self.user, self.server)

        now = timezone.now()
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=5),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.success",
            username="alice",
            source_ip="203.0.113.10",
            message="Accepted publickey for alice",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=4),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.fail",
            username="bob",
            source_ip="198.51.100.5",
            message="Failed password for bob",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=3),
            source_kind="file",
            source_name="/var/log/auth.log",
            category="network",
            event_type="network",
            message="Interface eth0 changed",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=2),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="203.0.113.10",
            message='192.0.2.40 - - [15/Apr/2026:23:57:44 +0000] "GET /api/v1/agent/servers/6/log-config HTTP/2.0" 200 682 "-"',
            fields={"nginx.status": "200"},
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=1),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="198.51.100.5",
            message='192.0.2.41 - - [15/Apr/2026:23:57:45 +0000] "GET /private HTTP/2.0" 401 245 "-"',
            fields={"nginx.status": "401"},
        )

    def _build_ca_material(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Keywarden Test Agent CA")])
        now = datetime.utcnow()
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")
        return ca_cert, ca_key, ca_pem, key_pem

    def _build_csr(self, common_name: str = "agent.example.test"):
        agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
            .sign(agent_key, hashes.SHA256())
        )
        return csr

    def test_ip_and_truncation_helpers(self) -> None:
        self.assertEqual(agent_router._normalize_ip("203.0.113.10", 4), "203.0.113.10")
        self.assertEqual(agent_router._normalize_ip("2001:db8::10", 6), "2001:db8::10")
        self.assertIsNone(agent_router._normalize_ip("not-ip", 4))
        self.assertEqual(agent_router._normalize_ip_any(" 203.0.113.11 "), "203.0.113.11")
        self.assertIsNone(agent_router._normalize_ip_any("bad-value"))
        self.assertEqual(agent_router._truncate(" abc ", 3), "abc")
        self.assertEqual(agent_router._truncate(None, 5, default="  xyz "), "xyz")

    def test_parse_event_at_and_fields_coercion(self) -> None:
        fallback = datetime(2026, 4, 17, 12, 0, 0)
        parsed = agent_router._parse_event_at("2026-04-17T12:34:56Z", fallback)
        self.assertEqual(parsed.isoformat(), "2026-04-17T12:34:56+00:00")
        fallback_parsed = agent_router._parse_event_at("not-a-time", fallback)
        self.assertTrue(timezone.is_aware(fallback_parsed))
        coerced = agent_router._coerce_fields({"A": 1, "B": True, "": "skip"})
        self.assertEqual(coerced, {"A": "1", "B": "True"})
        self.assertEqual(agent_router._coerce_fields(None), {})

    def test_source_kind_name_and_match_cleaning_helpers(self) -> None:
        self.assertEqual(agent_router._normalize_source_kind("service", None, None), "service")
        self.assertEqual(agent_router._normalize_source_kind(None, "sshd.service", None), "service")
        self.assertEqual(agent_router._normalize_source_kind(None, None, {"_TRANSPORT": "journal"}), "journal")
        self.assertEqual(agent_router._normalize_source_kind(None, None, {"file_path": "/var/log/auth.log"}), "file")
        self.assertEqual(agent_router._normalize_source_kind(None, None, None), "")

        self.assertEqual(agent_router._normalize_source_name("  sshd  ", "x", {}), "sshd")
        self.assertEqual(agent_router._normalize_source_name(None, "sudo.service", {}), "sudo.service")
        self.assertEqual(agent_router._normalize_source_name(None, None, {"_SYSTEMD_UNIT": "ssh.service"}), "ssh.service")
        self.assertEqual(agent_router._normalize_source_name(None, None, {"file_path": "/var/log/auth.log"}), "/var/log/auth.log")

        clean = agent_router._clean_source_matches({"_TRANSPORT": [" kernel ", ""], "UNIT": " sshd.service "})
        self.assertEqual(clean, {"_TRANSPORT": ["kernel"], "UNIT": ["sshd.service"]})
        self.assertEqual(agent_router._clean_source_matches(None), {})

    def test_default_category_and_event_type_helpers(self) -> None:
        journal = SimpleNamespace(
            kind=ServerLogSource.Kind.JOURNAL,
            service_unit="",
            include_matches={"_TRANSPORT": ["kernel"]},
        )
        service_ssh = SimpleNamespace(
            kind=ServerLogSource.Kind.SERVICE,
            service_unit="sshd.service",
            include_matches={},
        )
        service_sudo = SimpleNamespace(
            kind=ServerLogSource.Kind.SERVICE,
            service_unit="sudo.service",
            include_matches={},
        )
        file_source = SimpleNamespace(
            kind=ServerLogSource.Kind.FILE,
            service_unit="",
            include_matches={},
        )

        self.assertEqual(agent_router._default_category_for_source(journal), "system")
        self.assertEqual(agent_router._default_category_for_source(service_ssh), "access")
        self.assertEqual(agent_router._default_category_for_source(service_sudo), "auth")
        self.assertEqual(agent_router._default_event_type_for_source(journal), "kernel")
        self.assertEqual(agent_router._default_event_type_for_source(service_ssh), "ssh")
        self.assertEqual(agent_router._default_event_type_for_source(service_sudo), "auth")
        self.assertEqual(agent_router._default_event_type_for_source(file_source), "file.line")

    def test_agent_access_guards_and_token_generation(self) -> None:
        with self.assertRaises(HttpError) as unauth:
            agent_router._require_agent_access(SimpleNamespace(auth=None), self.server.id)
        self.assertEqual(unauth.exception.status_code, 401)

        with self.assertRaises(HttpError) as forbidden:
            agent_router._require_agent_access(
                SimpleNamespace(auth=agent_router.AgentPrincipal(server_id=999, mode="mtls")),
                self.server.id,
            )
        self.assertEqual(forbidden.exception.status_code, 403)

        agent_router._require_agent_access(
            SimpleNamespace(auth=agent_router.AgentPrincipal(server_id=self.server.id, mode="mtls")),
            self.server.id,
        )
        agent_router._require_agent_access(
            SimpleNamespace(auth=agent_router.AgentPrincipal(server_id=None, mode="global-token")),
            self.server.id,
        )
        self.assertNotEqual(agent_router._issue_agent_api_token(), agent_router._issue_agent_api_token())

    def test_server_lookup_key_map_and_account_sync_helpers(self) -> None:
        found = agent_router._get_server_or_404(self.server.id)
        self.assertEqual(found.id, self.server.id)
        with self.assertRaises(HttpError) as not_found:
            agent_router._get_server_or_404(999999)
        self.assertEqual(not_found.exception.status_code, 404)

        key_active = SSHKey.objects.create(
            user=self.user,
            name="active",
            public_key="ssh-ed25519 AAAA",
            key_type="ssh-ed25519",
            fingerprint="fp-active",
            is_active=True,
            revoked_at=None,
        )
        SSHKey.objects.create(
            user=self.user,
            name="revoked",
            public_key="ssh-ed25519 BBBB",
            key_type="ssh-ed25519",
            fingerprint="fp-revoked",
            is_active=True,
            revoked_at=timezone.now(),
        )
        key_map = agent_router._key_map_for_users([self.user])
        self.assertIn(self.user.id, key_map)
        self.assertEqual([item.id for item in key_map[self.user.id]], [key_active.id])

        payload = [agent_router.AccountSyncIn(user_id=self.user.id, system_username="helper_1", present=True)]
        agent_router._update_server_accounts(self.server, payload)
        account = self.server.accounts.get(user=self.user)
        self.assertEqual(account.system_username, "helper_1")
        self.assertTrue(account.is_present)

    def test_csr_and_agent_ca_helpers(self) -> None:
        with self.assertRaises(HttpError) as bad_csr:
            agent_router._load_csr("not a csr")
        self.assertEqual(bad_csr.exception.status_code, 422)

        with patch("keywarden.api.routers.agent.x509.load_pem_x509_csr", return_value=SimpleNamespace(is_signature_valid=False)):
            with self.assertRaises(HttpError) as bad_sig:
                agent_router._load_csr("dummy")
            self.assertEqual(bad_sig.exception.status_code, 422)

        ca_cert, ca_key, ca_pem, key_pem = self._build_ca_material()
        ca_record = agent_router.AgentCertificateAuthority.objects.create(
            name="Test Agent CA",
            cert_pem=ca_pem,
            key_pem=key_pem,
            is_active=True,
        )
        loaded_cert, loaded_key, loaded_pem = agent_router._load_agent_ca()
        self.assertEqual(loaded_pem, ca_record.cert_pem)
        self.assertIsNotNone(loaded_cert)
        self.assertIsNotNone(loaded_key)

        csr = self._build_csr("agent-1.example.test")
        with patch("keywarden.api.routers.agent._load_agent_ca", return_value=(ca_cert, ca_key, ca_pem)):
            cert_pem, returned_ca_pem, fingerprint, serial = agent_router._issue_client_cert(
                csr=csr,
                host="agent-1.example.test",
                server_id=self.server.id,
            )
        self.assertIn("BEGIN CERTIFICATE", cert_pem)
        self.assertEqual(returned_ca_pem, ca_pem)
        self.assertTrue(fingerprint)
        self.assertTrue(serial)

    def test_enroll_agent_rotates_existing_server_when_server_id_is_provided(self) -> None:
        ca_cert, _ca_key, ca_pem, key_pem = self._build_ca_material()
        agent_router.AgentCertificateAuthority.objects.create(
            name="Enroll CA",
            cert_pem=ca_pem,
            key_pem=key_pem,
            is_active=True,
        )
        token = EnrollmentToken.objects.create(token="rotate-token")
        original_server_count = Server.objects.count()
        self.server.agent_cert_fingerprint = "deadbeef"
        self.server.agent_cert_serial = "1"
        self.server.save(update_fields=["agent_cert_fingerprint", "agent_cert_serial"])

        csr = self._build_csr("rotate-agent.example.test")
        payload = {
            "token": token.token,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "server_id": str(self.server.id),
            "host": self.server.hostname,
        }
        response = self.client.post(
            "/api/v1/agent/enroll",
            data=json.dumps(payload),
            content_type="application/json",
        )

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body["server_id"], str(self.server.id))
        self.assertIn("BEGIN CERTIFICATE", body["client_cert_pem"])
        self.assertIn("BEGIN CERTIFICATE", body["ca_cert_pem"])
        self.assertTrue(body["agent_api_token"])
        self.assertEqual(Server.objects.count(), original_server_count)

        self.server.refresh_from_db()
        self.assertNotEqual(self.server.agent_cert_fingerprint, "deadbeef")
        self.assertNotEqual(self.server.agent_cert_serial, "1")
        self.assertIsNotNone(self.server.agent_enrolled_at)
        token.refresh_from_db()
        self.assertEqual(token.server_id, self.server.id)
        self.assertIsNotNone(token.used_at)

    def test_enroll_agent_rejects_invalid_server_id(self) -> None:
        token = EnrollmentToken.objects.create(token="rotate-token-bad")
        csr = self._build_csr("rotate-agent.example.test")
        payload = {
            "token": token.token,
            "csr_pem": csr.public_bytes(serialization.Encoding.PEM).decode("utf-8"),
            "server_id": "not-a-number",
        }
        response = self.client.post(
            "/api/v1/agent/enroll",
            data=json.dumps(payload),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 422)
        self.assertIn("server_id must be numeric", response.content.decode("utf-8"))


class KeysModelHelpersTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        User = get_user_model()
        self.user = User.objects.create_user(
            username="keys-user",
            email="keys-user@example.com",
            password="pass12345",
        )
        self.server = Server.objects.create(display_name="keys-server", hostname="keys-server.example.test")
        assign_perm("view_server", self.user, self.server)
        now = timezone.now()
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=5),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.success",
            username="alice",
            source_ip="203.0.113.10",
            message="Accepted publickey for alice",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=4),
            source_kind="service",
            source_name="sshd.service",
            category="access",
            event_type="ssh.login.fail",
            username="bob",
            source_ip="198.51.100.5",
            message="Failed password for bob",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=3),
            source_kind="file",
            source_name="/var/log/auth.log",
            category="network",
            event_type="network",
            message="Interface eth0 changed",
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=2),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="203.0.113.10",
            message='192.0.2.40 - - [15/Apr/2026:23:57:44 +0000] "GET /api/v1/agent/servers/6/log-config HTTP/2.0" 200 682 "-"',
            fields={"nginx.status": "200"},
        )
        ServerAuditLog.objects.create(
            server=self.server,
            event_at=now - timedelta(minutes=1),
            source_kind="file",
            source_name="/var/log/nginx/access.log",
            category="access",
            event_type="http.access",
            source_ip="198.51.100.5",
            message='192.0.2.41 - - [15/Apr/2026:23:57:45 +0000] "GET /private HTTP/2.0" 401 245 "-"',
            fields={"nginx.status": "401"},
        )

    def test_parse_public_key_valid_and_invalid(self) -> None:
        key_type, key_b64, fingerprint = parse_public_key("ssh-ed25519 AAAA comment")
        self.assertEqual(key_type, "ssh-ed25519")
        self.assertEqual(key_b64, "AAAA")
        self.assertTrue(fingerprint.startswith("SHA256:"))
        with self.assertRaises(ValidationError):
            parse_public_key("invalid-key")

    def test_sshkey_set_public_key_and_revoke(self) -> None:
        key = SSHKey.objects.create(
            user=self.user,
            name="laptop",
            public_key="ssh-ed25519 AAAA",
            key_type="ssh-ed25519",
            fingerprint="fp-laptop",
            is_active=True,
        )
        key.set_public_key("ssh-ed25519 AAAA comment-to-drop")
        self.assertEqual(key.public_key, "ssh-ed25519 AAAA")
        now = timezone.now()
        cert = SSHCertificate.objects.create(
            key=key,
            user=self.user,
            certificate="ssh-ed25519-cert-v01 AAAA",
            serial=42,
            principals=["keys_user"],
            valid_after=now - timedelta(minutes=1),
            valid_before=now + timedelta(days=1),
            is_active=True,
        )
        key.revoke()
        key.save(update_fields=["is_active", "revoked_at"])
        key.refresh_from_db()
        cert.refresh_from_db()
        self.assertFalse(key.is_active)
        self.assertIsNotNone(key.revoked_at)
        self.assertFalse(cert.is_active)
        self.assertIsNotNone(cert.revoked_at)

    def test_ssh_certificate_authority_ensure_material_paths(self) -> None:
        ca = SSHCertificateAuthority(
            name="Existing CA",
            public_key="ssh-ed25519 AAAA",
            private_key="-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE\n-----END OPENSSH PRIVATE KEY-----\n",
            fingerprint="",
        )
        ca.ensure_material()
        self.assertTrue(ca.fingerprint.startswith("SHA256:"))
        self.assertTrue(ca.private_key.startswith("file://"))

        generated = SSHCertificateAuthority(name="Generated CA")

        def fake_run(cmd, check, capture_output):
            key_path = cmd[cmd.index("-f") + 1]
            with open(key_path, "w", encoding="utf-8") as handle:
                handle.write("PRIVATE-KEY\n")
            with open(key_path + ".pub", "w", encoding="utf-8") as handle:
                handle.write("ssh-ed25519 AAAA generated-ca\n")
            return SimpleNamespace(returncode=0)

        with patch("apps.keys.models.subprocess.run", side_effect=fake_run):
            generated.ensure_material()
        self.assertTrue(generated.private_key)
        self.assertEqual(generated.public_key, "ssh-ed25519 AAAA generated-ca")
        self.assertTrue(generated.fingerprint.startswith("SHA256:"))

    def test_ssh_certificate_revoke(self) -> None:
        key = SSHKey.objects.create(
            user=self.user,
            name="desktop",
            public_key="ssh-ed25519 AAAA",
            key_type="ssh-ed25519",
            fingerprint="fp-desktop",
            is_active=True,
        )
        cert = SSHCertificate.objects.create(
            key=key,
            user=self.user,
            certificate="ssh-ed25519-cert-v01 AAAA",
            serial=77,
            principals=["keys_user"],
            valid_after=timezone.now() - timedelta(minutes=1),
            valid_before=timezone.now() + timedelta(days=1),
            is_active=True,
        )
        cert.revoke()
        self.assertFalse(cert.is_active)
        self.assertIsNotNone(cert.revoked_at)

    def test_audit_panel_view_supports_source_filters(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("servers:audit_panel", args=[self.server.id]),
            {
                "source_kind": "file",
                "source_name": "/var/log/auth.log",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/var/log/auth.log")
        self.assertContains(response, "Interface eth0 changed")
        self.assertNotContains(response, "Accepted publickey for alice")

    def test_audit_view_exposes_chart_context(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("servers:audit", args=[self.server.id]),
            {"view": "charts"},
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.context["audit_subpage"], "charts")

        charts = response.context["audit_charts"]
        login = charts["login_attempts"]
        self.assertEqual(login["total_attempts"], 2)
        self.assertEqual(login["failed_attempts"], 1)
        self.assertEqual(login["successful_attempts"], 1)
        self.assertEqual(login["failure_rate_pct"], 50)
        self.assertEqual(login["chart"]["drilldowns"][0], "view=logs&login_outcome=attempts")

        status_labels = charts["http_status_codes"]["chart"]["labels"]
        status_counts = charts["http_status_codes"]["chart"]["values"]
        status_map = dict(zip(status_labels, status_counts))
        self.assertEqual(status_map["401"], 1)
        self.assertNotIn("200", status_map)
        self.assertEqual(charts["http_status_codes"]["implicit_total"], 1)

    def test_audit_view_drilldown_filters_logs_for_http_status(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("servers:audit", args=[self.server.id]),
            {"view": "logs", "http_status": "401"},
        )
        self.assertEqual(response.status_code, 200)
        logs = list(response.context["initial_panel"]["logs"])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].event_type, "http.access")
        self.assertIn(" 401 ", logs[0].message)

    def test_audit_view_drilldown_filters_logs_for_login_outcome(self) -> None:
        self.client.force_login(self.user)
        response = self.client.get(
            reverse("servers:audit", args=[self.server.id]),
            {"view": "logs", "login_outcome": "success"},
        )
        self.assertEqual(response.status_code, 200)
        logs = list(response.context["initial_panel"]["logs"])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].event_type, "ssh.login.success")

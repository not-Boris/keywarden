from __future__ import annotations

import json
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from guardian.shortcuts import assign_perm

from apps.servers.models import Server, ServerAuditLog, ServerLogSource
from keywarden.api.security import hash_agent_token


class AgentLogIngestionTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.server = Server.objects.create(display_name="web-01", hostname="web-01.example.test")
        self.agent_token = "test-agent-token"
        self.server.agent_api_token_hash = hash_agent_token(self.agent_token)
        self.server.save(update_fields=["agent_api_token_hash"])
        self.agent_auth = f"Bearer {self.agent_token}"

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
            HTTP_AUTHORIZATION=self.agent_auth,
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
            HTTP_AUTHORIZATION=self.agent_auth,
        )
        self.assertEqual(response.status_code, 404)

    def test_ingest_logs_requires_agent_token(self) -> None:
        response = self.client.post(
            f"/api/v1/agent/servers/{self.server.id}/logs",
            data=json.dumps([]),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 401)

    def test_ingest_logs_rejects_token_for_different_server(self) -> None:
        other_server = Server.objects.create(display_name="web-02", hostname="web-02.example.test")
        other_server.agent_api_token_hash = hash_agent_token("other-server-token")
        other_server.save(update_fields=["agent_api_token_hash"])
        response = self.client.post(
            f"/api/v1/agent/servers/{self.server.id}/logs",
            data=json.dumps([]),
            content_type="application/json",
            HTTP_AUTHORIZATION="Bearer other-server-token",
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
            HTTP_AUTHORIZATION=self.agent_auth,
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
            HTTP_AUTHORIZATION=self.agent_auth,
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
        self.client.login(username="auditor", password="pass12345")
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

    def test_audit_panel_view_supports_source_filters(self) -> None:
        self.client.login(username="auditor", password="pass12345")
        response = self.client.get(
            reverse("servers:audit_panel", args=[self.server.id]),
            {
                "source_kind": "file",
                "source_name": "/var/log/auth.log",
            },
        )
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "/var/log/auth.log")
        self.assertNotContains(response, "ssh.login.success")

    def test_audit_view_exposes_chart_context(self) -> None:
        self.client.login(username="auditor", password="pass12345")
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
        self.client.login(username="auditor", password="pass12345")
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
        self.client.login(username="auditor", password="pass12345")
        response = self.client.get(
            reverse("servers:audit", args=[self.server.id]),
            {"view": "logs", "login_outcome": "success"},
        )
        self.assertEqual(response.status_code, 200)
        logs = list(response.context["initial_panel"]["logs"])
        self.assertEqual(len(logs), 1)
        self.assertEqual(logs[0].event_type, "ssh.login.success")

from __future__ import annotations

from django.http import HttpResponse
from django.test import RequestFactory, TestCase

from apps.audit.admin import AuditEventTypeAdminForm
from apps.audit.matching import find_matching_event_type
from apps.audit.middleware import ApiAuditLogMiddleware
from apps.audit.models import AuditEventType, AuditLog


class ApiAuditMiddlewareTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.factory = RequestFactory()
        self.middleware = ApiAuditLogMiddleware(lambda request: HttpResponse("ok"))

    def _call(self, method: str, path: str, ip: str = "203.0.113.5") -> None:
        request = self.factory.generic(method, path)
        request.META["REMOTE_ADDR"] = ip
        self.middleware(request)

    def test_no_matching_event_type_creates_no_logs_or_event_types(self) -> None:
        self._call("GET", "/api/auto/")
        self.assertEqual(AuditEventType.objects.count(), 0)
        self.assertEqual(AuditLog.objects.count(), 0)

    def test_matching_event_type_creates_log(self) -> None:
        event_type = AuditEventType.objects.create(
            key="api_test",
            title="API test",
            kind=AuditEventType.Kind.API,
            endpoints=["/api/test/"],
        )
        self._call("GET", "/api/test/")
        log = AuditLog.objects.get()
        self.assertEqual(log.event_type_id, event_type.id)
        self.assertEqual(log.source, AuditLog.Source.API)
        self.assertEqual(log.severity, event_type.default_severity)

    def test_ip_whitelist_blocks_and_allows(self) -> None:
        AuditEventType.objects.create(
            key="api_whitelist",
            title="API whitelist",
            kind=AuditEventType.Kind.API,
            endpoints=["/api/whitelist/"],
            ip_whitelist_enabled=True,
            ip_whitelist=["203.0.113.10"],
        )

        self._call("GET", "/api/whitelist/", ip="203.0.113.5")
        self.assertEqual(AuditLog.objects.count(), 0)

        self._call("GET", "/api/whitelist/", ip="203.0.113.10")
        self.assertEqual(AuditLog.objects.count(), 1)

    def test_ip_blacklist_blocks(self) -> None:
        AuditEventType.objects.create(
            key="api_blacklist",
            title="API blacklist",
            kind=AuditEventType.Kind.API,
            endpoints=["/api/blacklist/"],
            ip_blacklist_enabled=True,
            ip_blacklist=["203.0.113.5"],
        )

        self._call("GET", "/api/blacklist/", ip="203.0.113.5")
        self.assertEqual(AuditLog.objects.count(), 0)


class AuditEventMatchingTests(TestCase):
    def test_websocket_event_type_can_match(self) -> None:
        event_type = AuditEventType.objects.create(
            key="ws_shell",
            title="WebSocket shell",
            kind=AuditEventType.Kind.WEBSOCKET,
            endpoints=["/ws/servers/*/shell/"],
        )
        matched = find_matching_event_type(
            kind=AuditEventType.Kind.WEBSOCKET,
            method="GET",
            route="/ws/servers/123/shell/",
            path="/ws/servers/123/shell/",
            ip="203.0.113.10",
        )
        self.assertIsNotNone(matched)
        self.assertEqual(matched.id, event_type.id)


class AuditAdminFormTests(TestCase):
    def test_clean_endpoints_text_normalizes_lines(self) -> None:
        form = AuditEventTypeAdminForm(
            data={
                "key": "admin_form_test",
                "title": "Admin Form Test",
                "description": "",
                "kind": AuditEventType.Kind.API,
                "default_severity": AuditEventType.Severity.INFO,
                "endpoints_text": " /api/v1/a \n\nGET /api/v1/b \n",
                "ip_whitelist_enabled": False,
                "ip_whitelist_text": "",
                "ip_blacklist_enabled": False,
                "ip_blacklist_text": "",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        self.assertEqual(form.cleaned_data["endpoints_text"], "/api/v1/a\nGET /api/v1/b")

    def test_form_save_populates_endpoint_and_ip_lists(self) -> None:
        form = AuditEventTypeAdminForm(
            data={
                "key": "admin_form_save",
                "title": "Admin Form Save",
                "description": "",
                "kind": AuditEventType.Kind.API,
                "default_severity": AuditEventType.Severity.WARNING,
                "endpoints_text": "/api/v1/a\nPOST /api/v1/b",
                "ip_whitelist_enabled": True,
                "ip_whitelist_text": "10.0.0.1\n10.0.0.0/24",
                "ip_blacklist_enabled": True,
                "ip_blacklist_text": "203.0.113.10",
            }
        )
        self.assertTrue(form.is_valid(), form.errors)
        instance = form.save()
        self.assertEqual(instance.endpoints, ["/api/v1/a", "POST /api/v1/b"])
        self.assertEqual(instance.ip_whitelist, ["10.0.0.1", "10.0.0.0/24"])
        self.assertEqual(instance.ip_blacklist, ["203.0.113.10"])

    def test_form_initializes_text_fields_from_instance(self) -> None:
        instance = AuditEventType.objects.create(
            key="admin_form_init",
            title="Admin Form Init",
            kind=AuditEventType.Kind.WEBSOCKET,
            endpoints=["/ws/servers/*/shell/"],
            ip_whitelist=["10.0.0.1"],
            ip_blacklist=["203.0.113.10"],
        )
        form = AuditEventTypeAdminForm(instance=instance)
        self.assertEqual(form.fields["endpoints_text"].initial, "/ws/servers/*/shell/")
        self.assertEqual(form.fields["ip_whitelist_text"].initial, "10.0.0.1")
        self.assertEqual(form.fields["ip_blacklist_text"].initial, "203.0.113.10")

from __future__ import annotations

from django.http import HttpResponse
from django.test import RequestFactory, TestCase

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

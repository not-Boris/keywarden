from __future__ import annotations

import time

from django.utils import timezone

from .matching import find_matching_event_type
from .models import AuditEventType, AuditLog
from .utils import get_client_ip, get_request_id

_SKIP_PREFIXES = ("/api/v1/audit", "/api/v1/user")
_SKIP_SUFFIXES = ("/health", "/health/")

def _is_api_request(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _should_log_request(path: str) -> bool:
    # Only audit API traffic and skip endpoints that would recursively
    # generate noisy audit events (audit endpoints, health checks, etc.).
    if not _is_api_request(path):
        return False
    if path in _SKIP_PREFIXES:
        return False
    if any(path.startswith(prefix + "/") for prefix in _SKIP_PREFIXES):
        return False
    if any(path.endswith(suffix) for suffix in _SKIP_SUFFIXES):
        return False
    return True


def _resolve_route(request, fallback: str) -> str:
    match = getattr(request, "resolver_match", None)
    route = getattr(match, "route", None) if match else None
    if route:
        return route if route.startswith("/") else f"/{route}"
    return fallback


class ApiAuditLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Fast-exit for non-audited paths before taking timing measurements.
        path = request.path_info or request.path
        if not _should_log_request(path):
            return self.get_response(request)

        start = time.monotonic()
        try:
            response = self.get_response(request)
        except Exception as exc:
            duration_ms = int((time.monotonic() - start) * 1000)
            self._write_log(request, path, 500, duration_ms, error=type(exc).__name__)
            raise

        duration_ms = int((time.monotonic() - start) * 1000)
        self._write_log(request, path, response.status_code, duration_ms)
        return response

    def _write_log(self, request, path: str, status_code: int, duration_ms: int, error: str | None = None) -> None:
        try:
            route = _resolve_route(request, path)
            client_ip = get_client_ip(request)
            # Audit events are explicit: if no configured event type matches,
            # we do not create either an event type or a log entry.
            event_type = find_matching_event_type(
                kind=AuditEventType.Kind.API,
                method=request.method,
                route=route,
                path=path,
                ip=client_ip,
            )
            if event_type is None:
                return
            user = getattr(request, "user", None)
            actor = user if getattr(user, "is_authenticated", False) else None
            # Store normalized request context for filtering and forensics.
            metadata = {
                "method": request.method,
                "path": path,
                "route": route,
                "status_code": status_code,
                "duration_ms": duration_ms,
                "query_string": request.META.get("QUERY_STRING", ""),
            }
            if error:
                metadata["error"] = error
            AuditLog.objects.create(
                created_at=timezone.now(),
                actor=actor,
                event_type=event_type,
                message=f"API request {request.method} {route} -> {status_code}",
                severity=event_type.default_severity,
                source=AuditLog.Source.API,
                ip_address=client_ip,
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                request_id=get_request_id(request),
                metadata=metadata,
            )
        except Exception:
            return

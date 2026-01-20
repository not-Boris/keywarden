from __future__ import annotations

import hashlib
import time

from django.utils import timezone
from django.utils.text import slugify

from .models import AuditEventType, AuditLog
from .utils import get_client_ip, get_request_id

_EVENT_CACHE: dict[str, AuditEventType] = {}
_SKIP_PREFIXES = ("/api/v1/audit", "/api/v1/user")
_SKIP_SUFFIXES = ("/health", "/health/")

def _is_api_request(path: str) -> bool:
    return path == "/api" or path.startswith("/api/")


def _should_log_request(path: str) -> bool:
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


def _event_key_for(method: str, route: str) -> str:
    base = f"api_{method.lower()}_{route}"
    slug = slugify(base)
    if not slug:
        return "api_request"
    if len(slug) <= 64:
        return slug
    digest = hashlib.sha1(slug.encode("utf-8")).hexdigest()[:8]
    prefix_len = 64 - len(digest) - 1
    return f"{slug[:prefix_len]}-{digest}"


def _event_title_for(method: str, route: str) -> str:
    title = f"API {method.upper()} {route}"
    if len(title) <= 128:
        return title
    return f"{title[:125]}..."


def _get_endpoint_event(method: str, route: str) -> AuditEventType:
    key = _event_key_for(method, route)
    cached = _EVENT_CACHE.get(key)
    if cached is not None:
        return cached
    event, _ = AuditEventType.objects.get_or_create(
        key=key,
        defaults={
            "title": _event_title_for(method, route),
            "default_severity": AuditEventType.Severity.INFO,
        },
    )
    _EVENT_CACHE[key] = event
    return event


class ApiAuditLogMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
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
            user = getattr(request, "user", None)
            actor = user if getattr(user, "is_authenticated", False) else None
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
                event_type=_get_endpoint_event(request.method, route),
                message=f"API request {request.method} {route} -> {status_code}",
                severity=AuditEventType.Severity.INFO,
                source=AuditLog.Source.API,
                ip_address=get_client_ip(request),
                user_agent=request.META.get("HTTP_USER_AGENT", ""),
                request_id=get_request_id(request),
                metadata=metadata,
            )
        except Exception:
            return

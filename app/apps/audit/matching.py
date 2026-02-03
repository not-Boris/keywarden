from __future__ import annotations

import fnmatch
import ipaddress
import re
import time
from dataclasses import dataclass
from typing import Iterable

from django.urls import URLPattern, URLResolver, get_resolver

from .models import AuditEventType

_CACHE_TTL_SECONDS = 15.0
_METHOD_RE = re.compile(r"^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)\s+(.+)$", re.IGNORECASE)
_REGEX_GROUP_RE = re.compile(r"\(\?P<(?P<name>\w+)>[^)]+\)")
_CONVERTER_RE = re.compile(r"<(?:(?P<converter>[^:>]+):)?(?P<name>[^>]+)>")


@dataclass(frozen=True)
class ParsedEndpointPattern:
    method: str | None
    pattern: str


def _normalize_path(value: str) -> str:
    candidate = (value or "").strip()
    if not candidate:
        return ""
    if "?" in candidate:
        candidate = candidate.split("?", 1)[0]
    if not candidate.startswith("/"):
        candidate = f"/{candidate}"
    # Collapse duplicate slashes without being clever.
    while "//" in candidate:
        candidate = candidate.replace("//", "/")
    return candidate


def _strip_regex_anchors(value: str) -> str:
    candidate = value.strip()
    if candidate.startswith("^"):
        candidate = candidate[1:]
    if candidate.endswith("$"):
        candidate = candidate[:-1]
    return candidate


def _placeholder_to_wildcard(value: str) -> str:
    candidate = _strip_regex_anchors(value)
    candidate = _REGEX_GROUP_RE.sub("*", candidate)
    candidate = _CONVERTER_RE.sub("*", candidate)
    return candidate


def parse_endpoint_pattern(raw_pattern: str) -> ParsedEndpointPattern | None:
    # Parse admin-provided patterns like:
    # - "/api/v1/servers/*"
    # - "GET /api/v1/servers/<int:server_id>/"
    # We normalize both Django-style placeholders and regex routes into
    # fnmatch-friendly wildcard patterns.
    if not raw_pattern:
        return None
    raw = raw_pattern.strip()
    if not raw:
        return None
    method: str | None = None
    endpoint = raw
    match = _METHOD_RE.match(raw)
    if match:
        method = match.group(1).upper()
        endpoint = match.group(2)
    endpoint = _normalize_path(_placeholder_to_wildcard(endpoint))
    if not endpoint:
        return None
    return ParsedEndpointPattern(method=method, pattern=endpoint)


def _endpoint_matches_pattern(pattern: ParsedEndpointPattern, method: str, route: str, path: str) -> bool:
    if pattern.method and pattern.method != method.upper():
        return False
    route_norm = _normalize_path(route)
    path_norm = _normalize_path(path)
    return fnmatch.fnmatch(route_norm, pattern.pattern) or fnmatch.fnmatch(path_norm, pattern.pattern)


def _parse_ip_entry(
    entry: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    raw = (entry or "").strip()
    if not raw:
        return None
    try:
        if "/" in raw:
            return ipaddress.ip_network(raw, strict=False)
        return ipaddress.ip_address(raw)
    except ValueError:
        return None


def _ip_in_entries(ip: str, entries: Iterable[str]) -> bool:
    try:
        candidate_ip = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for entry in entries:
        parsed = _parse_ip_entry(entry)
        if parsed is None:
            continue
        if isinstance(parsed, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
            if candidate_ip in parsed:
                return True
        elif candidate_ip == parsed:
            return True
    return False


def ip_allowed_for_event(event_type: AuditEventType, ip: str | None) -> bool:
    # Apply whitelist first (default deny when enabled), then blacklist
    # (explicit deny). If the IP cannot be determined, we only allow it
    # when no whitelist is enforced.
    if not ip:
        # If we cannot determine the IP, allow by default unless a whitelist is enforced.
        return not event_type.ip_whitelist_enabled
    if event_type.ip_whitelist_enabled and not _ip_in_entries(ip, event_type.ip_whitelist or []):
        return False
    if event_type.ip_blacklist_enabled and _ip_in_entries(ip, event_type.ip_blacklist or []):
        return False
    return True


def endpoint_matches_event(event_type: AuditEventType, method: str, route: str, path: str) -> bool:
    # Event types are opt-in: an empty endpoint list never matches.
    # We allow either the resolved Django route or the raw path to match
    # so patterns can be authored using whichever is more stable.
    patterns = event_type.endpoints or []
    if not patterns:
        return False
    for raw_pattern in patterns:
        parsed = parse_endpoint_pattern(str(raw_pattern))
        if parsed and _endpoint_matches_pattern(parsed, method, route, path):
            return True
    return False


_EVENT_TYPE_CACHE: dict[str, tuple[float, list[AuditEventType]]] = {}


def clear_event_type_cache(*_args, **_kwargs) -> None:
    _EVENT_TYPE_CACHE.clear()


def get_event_types_for_kind(kind: str) -> list[AuditEventType]:
    # Cache event-type catalogs briefly to avoid repeated DB hits on
    # high-volume request paths. The cache is cleared on save/delete.
    now = time.monotonic()
    cached = _EVENT_TYPE_CACHE.get(kind)
    if cached and (now - cached[0]) < _CACHE_TTL_SECONDS:
        return cached[1]
    event_types = list(AuditEventType.objects.filter(kind=kind).order_by("key"))
    _EVENT_TYPE_CACHE[kind] = (now, event_types)
    return event_types


def find_matching_event_type(kind: str, method: str, route: str, path: str, ip: str | None) -> AuditEventType | None:
    # Deterministic first-match semantics: the ordered catalog defines
    # precedence when multiple event types could match.
    for event_type in get_event_types_for_kind(kind):
        if not endpoint_matches_event(event_type, method=method, route=route, path=path):
            continue
        if not ip_allowed_for_event(event_type, ip):
            continue
        return event_type
    return None


def _join_paths(prefix: str, segment: str) -> str:
    if not prefix:
        return segment
    if not segment:
        return prefix
    return f"{prefix.rstrip('/')}/{segment.lstrip('/')}"


def _walk_urlpatterns(patterns: Iterable[URLPattern | URLResolver], prefix: str = "") -> list[str]:
    # Flatten the resolver tree into full route strings so the admin
    # UI can offer endpoint suggestions without hardcoding routes.
    results: list[str] = []
    for pattern in patterns:
        segment = str(pattern.pattern)
        combined = _join_paths(prefix, segment)
        if isinstance(pattern, URLResolver):
            results.extend(_walk_urlpatterns(pattern.url_patterns, combined))
        else:
            results.append(combined)
    return results


def _normalize_suggestion(value: str) -> str:
    candidate = _strip_regex_anchors(value)
    candidate = candidate.replace("\\", "")
    candidate = _REGEX_GROUP_RE.sub(lambda m: f"<{m.group('name')}>", candidate)
    candidate = _normalize_path(candidate)
    return candidate


def list_api_endpoint_suggestions() -> list[str]:
    # Introspect the URL resolver and keep only API routes. Suggestions
    # are normalized to human-editable patterns (e.g., "<server_id>").
    resolver = get_resolver()
    raw_patterns = _walk_urlpatterns(resolver.url_patterns)
    suggestions: set[str] = set()
    for pattern in raw_patterns:
        if not pattern:
            continue
        normalized = _normalize_suggestion(pattern)
        if normalized.startswith("/api"):
            suggestions.add(normalized)
    return sorted(s for s in suggestions if s)


def list_websocket_endpoint_suggestions() -> list[str]:
    # WebSocket routes are maintained separately by Channels, so we
    # import them directly from the ASGI routing module.
    try:
        from keywarden.routing import websocket_urlpatterns
    except Exception:
        return []
    raw_patterns = [str(p.pattern) for p in websocket_urlpatterns]
    suggestions = {_normalize_suggestion(p) for p in raw_patterns}
    return sorted(s for s in suggestions if s)

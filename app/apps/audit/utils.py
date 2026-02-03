from __future__ import annotations

import ipaddress


def _normalize_ip(value: str | None) -> str | None:
    if not value:
        return None
    candidate = value.strip()
    if not candidate:
        return None
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and candidate.rsplit(":", 1)[1].isdigit():
        candidate = candidate.rsplit(":", 1)[0]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return None


def get_client_ip(request) -> str | None:
    if not request:
        return None
    x_real_ip = _normalize_ip(request.META.get("HTTP_X_REAL_IP"))
    if x_real_ip:
        return x_real_ip
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR", "")
    if forwarded_for:
        for part in forwarded_for.split(","):
            ip = _normalize_ip(part)
            if ip:
                return ip
    return _normalize_ip(request.META.get("REMOTE_ADDR"))


def get_request_id(request) -> str:
    if not request:
        return ""
    return (
        request.META.get("HTTP_X_REQUEST_ID")
        or request.META.get("HTTP_X_CORRELATION_ID")
        or ""
    )


def _get_scope_header(scope, header_name: str) -> str | None:
    headers = scope.get("headers") if scope else None
    if not headers:
        return None
    target = header_name.lower().encode("latin-1")
    for key, value in headers:
        if key.lower() == target:
            try:
                return value.decode("latin-1")
            except Exception:
                return None
    return None


def get_client_ip_from_scope(scope) -> str | None:
    if not scope:
        return None
    x_real_ip = _normalize_ip(_get_scope_header(scope, "x-real-ip"))
    if x_real_ip:
        return x_real_ip
    forwarded_for = _get_scope_header(scope, "x-forwarded-for") or ""
    if forwarded_for:
        for part in forwarded_for.split(","):
            ip = _normalize_ip(part)
            if ip:
                return ip
    client = scope.get("client")
    if isinstance(client, (list, tuple)) and client:
        return _normalize_ip(str(client[0]))
    return None


def get_request_id_from_scope(scope) -> str:
    if not scope:
        return ""
    return (
        _get_scope_header(scope, "x-request-id")
        or _get_scope_header(scope, "x-correlation-id")
        or ""
    )


def get_user_agent_from_scope(scope) -> str:
    if not scope:
        return ""
    return _get_scope_header(scope, "user-agent") or ""

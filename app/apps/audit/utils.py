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

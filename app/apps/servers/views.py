from __future__ import annotations

from datetime import timedelta

from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user, get_perms

from apps.access.models import AccessRequest
from apps.keys.utils import render_system_username
from apps.keys.models import SSHKey
from apps.servers.models import Server, ServerAccount
from apps.servers.permissions import user_can_shell


@login_required(login_url="/accounts/login/")
def dashboard(request):
    now = timezone.now()
    server_qs = get_objects_for_user(
        request.user,
        "servers.view_server",
        klass=Server,
        accept_global_perms=False,
    )

    access_qs = (
        AccessRequest.objects.select_related("server")
        .filter(
            requester=request.user,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
    )
    expires_map = {}
    for access in access_qs:
        expires_at = access.expires_at
        if access.server_id not in expires_map:
            expires_map[access.server_id] = expires_at
            continue
        current = expires_map[access.server_id]
        if current is None:
            continue
        if expires_at is None or expires_at > current:
            expires_map[access.server_id] = expires_at

    servers = []
    for server in server_qs:
        servers.append(
            {
                "server": server,
                "expires_at": expires_map.get(server.id),
                "last_accessed": None,
                "status": _build_server_status(server, now),
            }
        )

    context = {
        "servers": servers,
    }
    return render(request, "servers/dashboard.html", context)


@login_required(login_url="/accounts/login/")
def detail(request, server_id: int):
    now = timezone.now()
    # Authorization is enforced via object-level permissions before we do
    # any other server-specific work.
    server = _get_server_or_404(request, server_id)
    can_shell = user_can_shell(request.user, server, now)

    access = (
        AccessRequest.objects.filter(
            requester=request.user,
            server_id=server_id,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-requested_at")
        .first()
    )

    account, system_username, certificate_key_id = _load_account_context(request, server)
    context = {
        "server": server,
        "expires_at": access.expires_at if access else None,
        "last_accessed": None,
        "account_present": account.is_present if account else None,
        "account_synced_at": account.last_synced_at if account else None,
        "system_username": system_username,
        "certificate_key_id": certificate_key_id,
        "active_tab": "details",
        "can_shell": can_shell,
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/detail.html", context)


@login_required(login_url="/accounts/login/")
def shell(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    # We intentionally return a 404 on denied shell access to avoid
    # disclosing that the server exists but is restricted.
    if not user_can_shell(request.user, server):
        raise Http404("Shell access not available")
    _, system_username, certificate_key_id = _load_account_context(request, server)
    shell_target = server.hostname or server.ipv4 or server.ipv6 or ""
    cert_filename = ""
    if certificate_key_id:
        cert_filename = f"keywarden-{request.user.id}-{certificate_key_id}-cert.pub"
    command = ""
    if shell_target and system_username and certificate_key_id:
        command = (
            "ssh -i /path/to/private_key "
            f"-o CertificateFile=~/Downloads/{cert_filename} "
            f"{system_username}@{shell_target} -t /bin/bash"
        )
    context = {
        "server": server,
        "system_username": system_username,
        "certificate_key_id": certificate_key_id,
        "shell_target": shell_target,
        "shell_command": command,
        "cert_filename": cert_filename,
        "active_tab": "shell",
        "is_popout": request.GET.get("popout") == "1",
        "can_shell": True,
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/shell.html", context)


@login_required(login_url="/accounts/login/")
def audit(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    context = {
        "server": server,
        "active_tab": "audit",
        "can_shell": user_can_shell(request.user, server),
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/audit.html", context)


@login_required(login_url="/accounts/login/")
def settings(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    context = {
        "server": server,
        "active_tab": "settings",
        "can_shell": user_can_shell(request.user, server),
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/settings.html", context)


def _get_server_or_404(request, server_id: int) -> Server:
    # Centralized object lookup + permission gate. We raise 404 for both
    # missing objects and permission denials to reduce enumeration signals.
    try:
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise Http404("Server not found")
    if "view_server" not in get_perms(request.user, server):
        raise Http404("Server not found")
    return server


def _load_account_context(request, server: Server):
    # Resolve the effective system username and the currently active SSH
    # key/certificate context used by the shell UI.
    account = ServerAccount.objects.filter(server=server, user=request.user).first()
    system_username = account.system_username if account else render_system_username(
        request.user.username, request.user.id
    )
    active_key = SSHKey.objects.filter(user=request.user, is_active=True).order_by("-created_at").first()
    certificate_key_id = active_key.id if active_key else None
    return account, system_username, certificate_key_id


def _format_age_short(delta: timedelta) -> str:
    seconds = max(0, int(delta.total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes = seconds // 60
    if minutes < 60:
        return f"{minutes}m"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h"
    days = hours // 24
    if days < 14:
        return f"{days}d"
    weeks = days // 7
    return f"{weeks}w"


def _build_server_status(server: Server, now):
    stale_seconds = int(getattr(settings, "KEYWARDEN_HEARTBEAT_STALE_SECONDS", 120))
    heartbeat_at = getattr(server, "last_heartbeat_at", None)
    ping_ms = getattr(server, "last_ping_ms", None)
    if heartbeat_at:
        age = now - heartbeat_at
        age_seconds = max(0, int(age.total_seconds()))
        is_active = age_seconds <= stale_seconds
        age_short = _format_age_short(age)
    else:
        is_active = False
        age_short = "never"
    label = "Active" if is_active else "Inactive"
    if is_active:
        detail = f"{ping_ms}ms" if ping_ms is not None else "—"
    else:
        detail = age_short
    return {
        "is_active": is_active,
        "label": label,
        "detail": detail,
        "ping_ms": ping_ms,
        "age_short": age_short,
        "heartbeat_at": heartbeat_at,
    }

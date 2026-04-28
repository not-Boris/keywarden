from __future__ import annotations

import re
from collections import Counter
from datetime import datetime, time, timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Count, Q
from django.http import Http404
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.dateparse import parse_date, parse_datetime
from django.views.decorators.http import require_POST
from guardian.shortcuts import get_objects_for_user, get_users_with_perms

from apps.access.models import AccessRequest
from apps.access.permissions import sync_server_view_perm
from apps.accounts.forms import NativePasswordResetForm
from apps.accounts.models import ErasureRequest
from apps.keys.utils import render_system_username
from apps.keys.models import SSHKey
from apps.servers.models import Server, ServerAccount, ServerAuditLog
from apps.servers.permissions import user_can_logs, user_can_shell, user_can_users, user_has_any_access

AUDIT_LINE_LIMIT_OPTIONS = (25, 50, 100, 200)
DEFAULT_AUDIT_LINE_LIMIT = 100
AUDIT_SUBPAGE_OPTIONS = {"charts", "logs"}
SSH_LOGIN_EVENT_TYPES = ("ssh.login.success", "ssh.login.fail")
HTTP_STATUS_PATTERN = re.compile(r'"\s*(\d{3})\s+\S+')
LOGIN_OUTCOME_OPTIONS = {"attempts", "success", "failed"}
REQUEST_DURATION_HOURS_OPTIONS = (1, 4, 8, 24, 72, 168)


def _is_admin_user(user) -> bool:
    if not user or not getattr(user, "is_authenticated", False):
        return False
    return bool(
        user.is_superuser
        or user.is_staff
        or user.has_perm("servers.change_server")
        or user.has_perm("access.change_accessrequest")
    )


def _require_admin_or_404(request) -> None:
    if _is_admin_user(request.user):
        return
    raise Http404("Not found")


@login_required(login_url="/accounts/login/")
def dashboard(request):
    now = timezone.now()
    user = request.user
    if user.has_perm("access.add_accessrequest") or user.has_perm("servers.view_server"):
        server_qs = Server.objects.all()
    else:
        server_qs = Server.objects.none()

    access_qs = (
        AccessRequest.objects.filter(
            requester=user,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-requested_at")
    )
    access_state_map: dict[int, dict] = {}
    request_governed_server_ids: set[int] = set()
    for access in access_qs:
        server_id = access.server_id
        request_governed_server_ids.add(server_id)
        state = access_state_map.setdefault(
            server_id,
            {
                "can_shell": False,
                "can_logs": False,
                "can_users": False,
                "expires_at": access.expires_at,
            },
        )
        state["can_shell"] = state["can_shell"] or bool(access.request_shell)
        state["can_logs"] = state["can_logs"] or bool(access.request_logs)
        state["can_users"] = state["can_users"] or bool(access.request_users)
        current_expires = state["expires_at"]
        if current_expires is None:
            continue
        if access.expires_at is None or access.expires_at > current_expires:
            state["expires_at"] = access.expires_at

    pending_access_qs = AccessRequest.objects.filter(
        requester=user,
        status=AccessRequest.Status.PENDING,
    ).order_by("-requested_at")
    pending_access_by_server: dict[int, AccessRequest] = {}
    for access in pending_access_qs:
        if access.server_id not in pending_access_by_server:
            pending_access_by_server[access.server_id] = access

    has_global_change = user.has_perm("servers.change_server")
    has_global_view = user.has_perm("servers.view_server")
    has_global_shell = user.has_perm("servers.shell_server")
    if has_global_view:
        view_perm_server_ids: set[int] = set()
    else:
        view_perm_server_ids = set(
            get_objects_for_user(
                user,
                "servers.view_server",
                klass=Server,
                accept_global_perms=False,
            ).values_list("id", flat=True)
        )
    if has_global_shell:
        shell_perm_server_ids: set[int] = set()
    else:
        shell_perm_server_ids = set(
            get_objects_for_user(
                user,
                "servers.shell_server",
                klass=Server,
                accept_global_perms=False,
            ).values_list("id", flat=True)
        )

    servers = []
    for server in server_qs:
        state = access_state_map.get(
            server.id,
            {
                "can_shell": False,
                "can_logs": False,
                "can_users": False,
                "expires_at": None,
            },
        )
        has_manual_view = has_global_change or (
            (has_global_view or server.id in view_perm_server_ids)
            and server.id not in request_governed_server_ids
        )
        can_shell = bool(has_global_change or has_global_shell or server.id in shell_perm_server_ids or state["can_shell"])
        can_logs = bool(has_manual_view or state["can_logs"])
        can_users = bool(has_manual_view or state["can_users"])
        has_access = bool(has_manual_view or can_shell or can_logs or can_users)
        pending = pending_access_by_server.get(server.id)
        servers.append(
            {
                "server": server,
                "expires_at": state["expires_at"] if has_access else None,
                "last_accessed": None,
                "status": _build_server_status(server, now),
                "access": {
                    "granted": has_access,
                    "can_shell": can_shell,
                    "can_logs": can_logs,
                    "can_users": can_users,
                    "pending": pending,
                },
            }
        )

    return render(request, "servers/dashboard.html", {"servers": servers})


@login_required(login_url="/accounts/login/")
def admin_dashboard(request):
    _require_admin_or_404(request)
    now = timezone.now()
    active_view = (request.GET.get("view") or "pending").strip().lower()
    if active_view not in {"users", "servers", "pending", "grants"}:
        active_view = "pending"

    pending_access_requests = list(
        AccessRequest.objects.select_related("requester", "server")
        .filter(status=AccessRequest.Status.PENDING)
        .order_by("requested_at")
    )
    pending_access_request_rows = [
        {
            "request": pending_access_request,
            "scope_count": int(bool(pending_access_request.request_shell))
            + int(bool(pending_access_request.request_logs))
            + int(bool(pending_access_request.request_users)),
        }
        for pending_access_request in pending_access_requests
    ]
    active_grants_qs = (
        AccessRequest.objects.select_related("requester", "server")
        .filter(status=AccessRequest.Status.APPROVED)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .filter(Q(request_shell=True) | Q(request_logs=True) | Q(request_users=True))
        .order_by("requester__username", "server__display_name", "requested_at", "id")
    )
    active_grants = list(active_grants_qs)

    grant_servers_by_user_id: dict[int, set[str]] = {}
    grant_counts_by_user_id: dict[int, int] = {}
    for grant in active_grants:
        grant_counts_by_user_id[grant.requester_id] = grant_counts_by_user_id.get(grant.requester_id, 0) + 1
        grant_servers_by_user_id.setdefault(grant.requester_id, set()).add(grant.server.display_name)

    users = list(get_user_model().objects.order_by("username", "id"))
    pending_erasure_user_ids = set(
        ErasureRequest.objects.filter(status=ErasureRequest.Status.PENDING).values_list("user_id", flat=True)
    )
    user_rows = []
    for user in users:
        user_servers = sorted(grant_servers_by_user_id.get(user.id, set()), key=lambda value: value.lower())
        user_rows.append(
            {
                "user": user,
                "active_grants_count": grant_counts_by_user_id.get(user.id, 0),
                "active_grant_servers": user_servers,
                "active_grants_tooltip": ", ".join(user_servers) if user_servers else "No active grants",
                "has_pending_erasure_request": user.id in pending_erasure_user_ids,
            }
        )

    servers = list(Server.objects.order_by("display_name", "hostname", "id"))

    grant_user_filter_raw = (request.GET.get("grant_user") or "").strip()
    grant_user_filter_id = None
    try:
        if grant_user_filter_raw:
            grant_user_filter_id = int(grant_user_filter_raw)
    except (TypeError, ValueError):
        grant_user_filter_id = None

    grants_for_view = active_grants
    if grant_user_filter_id is not None:
        grants_for_view = [grant for grant in grants_for_view if grant.requester_id == grant_user_filter_id]

    last_used_lookup: dict[tuple[int, str], datetime] = {}
    if grants_for_view:
        grant_server_ids = {grant.server_id for grant in grants_for_view}
        grant_usernames = {grant.requester.username for grant in grants_for_view if grant.requester.username}
        if grant_server_ids and grant_usernames:
            audit_rows = (
                ServerAuditLog.objects.filter(server_id__in=grant_server_ids, username__in=grant_usernames)
                .exclude(username="")
                .values("server_id", "username", "event_at")
                .order_by("server_id", "username", "-event_at")
            )
            for audit_row in audit_rows:
                key = (audit_row["server_id"], audit_row["username"])
                if key in last_used_lookup:
                    continue
                last_used_lookup[key] = audit_row["event_at"]

    grant_rows = []
    for grant in grants_for_view:
        last_used_at = last_used_lookup.get((grant.server_id, grant.requester.username))
        expires_soon = False
        if grant.expires_at is not None:
            remaining = grant.expires_at - now
            expires_soon = timedelta(0) <= remaining <= timedelta(days=7)
        expires_at_input = ""
        if grant.expires_at is not None:
            expires_at_local = timezone.localtime(grant.expires_at, timezone.get_current_timezone())
            expires_at_input = expires_at_local.strftime("%Y-%m-%dT%H:%M")
        grant_rows.append(
            {
                "grant": grant,
                "last_used_at": last_used_at,
                "expires_soon": expires_soon,
                "expires_at_input": expires_at_input,
            }
        )

    grant_filter_users_by_id = {grant.requester_id: grant.requester for grant in active_grants}
    grant_filter_users = sorted(
        grant_filter_users_by_id.values(),
        key=lambda user: (user.username.lower(), user.id),
    )
    selected_grant_user = next(
        (user for user in grant_filter_users if user.id == grant_user_filter_id),
        None,
    )

    total_users = len(users)
    total_servers = len(servers)
    open_access_requests = len(pending_access_requests)
    active_access_grants = len(active_grants)

    utilities = [
        {
            "title": "Server Inventory",
            "description": "Manage server records, enrollment, and baseline metadata.",
            "url": reverse("admin:servers_server_changelist"),
        },
        {
            "title": "Enrollment Tokens",
            "description": "Create and rotate server enrollment tokens.",
            "url": reverse("admin:servers_enrollmenttoken_changelist"),
        },
        {
            "title": "Agent Certificate Authorities",
            "description": "Review and rotate the agent mTLS CA.",
            "url": reverse("admin:servers_agentcertificateauthority_changelist"),
        },
        {
            "title": "Log Source Policies",
            "description": "Configure central log source definitions and parsers.",
            "url": reverse("admin:servers_serverlogsource_changelist"),
        },
        {
            "title": "Access Request Records",
            "description": "Inspect historical access requests and lifecycle decisions.",
            "url": reverse("admin:access_accessrequest_changelist"),
        },
        {
            "title": "Django Admin",
            "description": "Open the full administrative backend.",
            "url": reverse("admin:index"),
        },
    ]
    context = {
        "active_view": active_view,
        "pending_access_requests": pending_access_request_rows,
        "users": user_rows,
        "servers": servers,
        "grant_rows": grant_rows,
        "grant_filter_users": grant_filter_users,
        "selected_grant_user": selected_grant_user,
        "grant_user_filter_id": grant_user_filter_id,
        "utilities": utilities,
        "summary": {
            "users": total_users,
            "servers": total_servers,
            "pending_requests": open_access_requests,
            "active_grants": active_access_grants,
        },
    }
    return render(request, "servers/admin.html", context)


@login_required(login_url="/accounts/login/")
@require_POST
def request_access(request, server_id: int):
    if not request.user.has_perm("access.add_accessrequest"):
        raise Http404("Server not found")
    try:
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise Http404("Server not found")
    now = timezone.now()
    if user_has_any_access(request.user, server, now):
        return redirect("servers:dashboard")
    if AccessRequest.objects.filter(
        requester=request.user,
        server=server,
        status=AccessRequest.Status.PENDING,
    ).exists():
        return redirect("servers:dashboard")
    scoped_request = (request.POST.get("scoped_request") or "").strip() == "1"
    if scoped_request:
        request_shell = (request.POST.get("request_shell") or "").strip().lower() in {"1", "true", "on", "yes"}
        request_logs = (request.POST.get("request_logs") or "").strip().lower() in {"1", "true", "on", "yes"}
        request_users = (request.POST.get("request_users") or "").strip().lower() in {"1", "true", "on", "yes"}
        if not any((request_shell, request_logs, request_users)):
            return redirect("servers:dashboard")
        reason = (request.POST.get("reason") or "").strip()
        requested_server_username = (request.POST.get("requested_server_username") or "").strip()[:128]
        requested_duration_hours = None
        raw_duration = (request.POST.get("requested_duration_hours") or "").strip()
        if raw_duration:
            try:
                parsed_duration = int(raw_duration)
            except (TypeError, ValueError):
                parsed_duration = None
            if parsed_duration in REQUEST_DURATION_HOURS_OPTIONS:
                requested_duration_hours = parsed_duration
    else:
        request_shell = True
        request_logs = True
        request_users = True
        reason = ""
        requested_server_username = ""
        requested_duration_hours = None
    AccessRequest.objects.create(
        requester=request.user,
        server=server,
        reason=reason,
        request_shell=request_shell,
        request_logs=request_logs,
        request_users=request_users,
        requested_duration_hours=requested_duration_hours,
        requested_server_username=requested_server_username,
    )
    return redirect("servers:dashboard")


@login_required(login_url="/accounts/login/")
@require_POST
def decide_access_request(request, request_id: int):
    if not _is_admin_user(request.user):
        raise Http404("Request not found")
    try:
        access_request = AccessRequest.objects.get(id=request_id)
    except AccessRequest.DoesNotExist:
        raise Http404("Request not found")
    if access_request.status != AccessRequest.Status.PENDING:
        return redirect(_next_redirect_target(request, access_request.server_id))
    action = (request.POST.get("action") or "").strip().lower()
    decision_at = timezone.now()
    update_fields = ["status", "decided_at", "decided_by"]
    if action == "approve":
        access_request.status = AccessRequest.Status.APPROVED
        if access_request.requested_duration_hours and not access_request.expires_at:
            access_request.expires_at = decision_at + timedelta(hours=access_request.requested_duration_hours)
            update_fields.append("expires_at")
    elif action == "deny":
        access_request.status = AccessRequest.Status.DENIED
    else:
        return redirect(_next_redirect_target(request, access_request.server_id))
    access_request.decided_at = decision_at
    access_request.decided_by = request.user
    access_request.save(update_fields=update_fields)
    sync_server_view_perm(access_request)
    return redirect(_next_redirect_target(request, access_request.server_id))


@login_required(login_url="/accounts/login/")
@require_POST
def admin_send_password_reset(request, user_id: int):
    _require_admin_or_404(request)
    user_model = get_user_model()
    try:
        target_user = user_model.objects.get(id=user_id)
    except user_model.DoesNotExist:
        raise Http404("User not found")

    reset_form = NativePasswordResetForm({"email": target_user.email})
    if reset_form.is_valid():
        reset_form.save(
            request=request,
            use_https=request.is_secure(),
            from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@localhost"),
            email_template_name="accounts/password_reset_email.txt",
            subject_template_name="accounts/password_reset_subject.txt",
        )
    return redirect(_admin_next_redirect_target(request))


@login_required(login_url="/accounts/login/")
@require_POST
def admin_delete_user(request, user_id: int):
    _require_admin_or_404(request)
    user_model = get_user_model()
    try:
        target_user = user_model.objects.get(id=user_id)
    except user_model.DoesNotExist:
        raise Http404("User not found")
    if target_user.id == request.user.id:
        return redirect(_admin_next_redirect_target(request))
    target_user.delete()
    return redirect(_admin_next_redirect_target(request))


@login_required(login_url="/accounts/login/")
@require_POST
def admin_delete_server(request, server_id: int):
    _require_admin_or_404(request)
    try:
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise Http404("Server not found")
    server.delete()
    return redirect(_admin_next_redirect_target(request))


@login_required(login_url="/accounts/login/")
@require_POST
def admin_revoke_grant(request, grant_id: int):
    _require_admin_or_404(request)
    try:
        grant = AccessRequest.objects.select_related("server", "requester").get(id=grant_id)
    except AccessRequest.DoesNotExist:
        raise Http404("Access grant not found")
    if grant.status == AccessRequest.Status.APPROVED:
        now = timezone.now()
        grant.status = AccessRequest.Status.REVOKED
        grant.decided_at = now
        grant.decided_by = request.user
        grant.expires_at = now
        grant.save(update_fields=["status", "decided_at", "decided_by", "expires_at"])
        sync_server_view_perm(grant)
    return redirect(_admin_next_redirect_target(request))


@login_required(login_url="/accounts/login/")
@require_POST
def admin_change_grant_expiry(request, grant_id: int):
    _require_admin_or_404(request)
    try:
        grant = AccessRequest.objects.select_related("server", "requester").get(id=grant_id)
    except AccessRequest.DoesNotExist:
        raise Http404("Access grant not found")

    raw_expires_at = (request.POST.get("expires_at") or "").strip()
    expires_at = _parse_filter_datetime(raw_expires_at, end_of_day=True) if raw_expires_at else None
    if grant.status == AccessRequest.Status.APPROVED:
        grant.expires_at = expires_at
        grant.save(update_fields=["expires_at"])
        sync_server_view_perm(grant)
    return redirect(_admin_next_redirect_target(request))


@login_required(login_url="/accounts/login/")
def detail(request, server_id: int):
    now = timezone.now()
    # Authorization is enforced via object-level permissions before we do
    # any other server-specific work.
    server = _get_server_or_404(request, server_id)
    can_shell = user_can_shell(request.user, server, now)
    can_logs = user_can_logs(request.user, server, now)
    can_users = user_can_users(request.user, server, now)
    if not can_users:
        raise Http404("Server not found")

    access = (
        AccessRequest.objects.filter(
            requester=request.user,
            server_id=server_id,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(request_shell=True) | Q(request_logs=True) | Q(request_users=True))
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
        "can_logs": can_logs,
        "can_users": can_users,
        "is_server_admin": _is_admin_user(request.user),
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/detail.html", context)


@login_required(login_url="/accounts/login/")
def shell(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    # We intentionally return a 404 on denied shell access to avoid
    # disclosing that the server exists but is restricted.
    can_shell = user_can_shell(request.user, server, now)
    can_logs = user_can_logs(request.user, server, now)
    can_users = user_can_users(request.user, server, now)
    if not can_shell:
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
        "can_shell": can_shell,
        "can_logs": can_logs,
        "can_users": can_users,
        "is_server_admin": _is_admin_user(request.user),
        "server_status": _build_server_status(server, now),
    }
    return render(request, "servers/shell.html", context)


@login_required(login_url="/accounts/login/")
def audit(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    can_logs = user_can_logs(request.user, server, now)
    if not can_logs:
        raise Http404("Server not found")
    subpage = (request.GET.get("view") or "").strip().lower()
    if subpage not in AUDIT_SUBPAGE_OPTIONS:
        subpage = "logs"
    panel_action = reverse("servers:audit_panel", args=[server.id])
    initial_panel = _build_audit_panel_context(request, server, panel_action=panel_action)
    audit_summary = _build_audit_summary(server, now)
    audit_charts = _build_audit_chart_context(server)
    context = {
        "server": server,
        "active_tab": "audit",
        "can_shell": user_can_shell(request.user, server, now),
        "can_logs": can_logs,
        "can_users": user_can_users(request.user, server, now),
        "is_server_admin": _is_admin_user(request.user),
        "server_status": _build_server_status(server, now),
        "initial_panel": initial_panel,
        "audit_summary": audit_summary,
        "audit_panel_url": panel_action,
        "audit_line_limit": initial_panel["line_limit"],
        "audit_line_limit_options": initial_panel["line_limit_options"],
        "audit_subpage": subpage,
        "audit_charts": audit_charts,
    }
    return render(request, "servers/audit.html", context)


@login_required(login_url="/accounts/login/")
def audit_panel(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    if not user_can_logs(request.user, server, now):
        raise Http404("Server not found")
    panel_action = reverse("servers:audit_panel", args=[server.id])
    panel = _build_audit_panel_context(request, server, panel_action=panel_action)
    return render(request, "servers/_audit_panel.html", {"server": server, "panel": panel})


@login_required(login_url="/accounts/login/")
def settings(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    can_users = user_can_users(request.user, server, now)
    if not can_users:
        raise Http404("Server not found")
    audit_summary = _build_audit_summary(server, now)
    log_sources = list(server.log_sources.filter(enabled=True).order_by("kind", "name", "id"))
    admin_server_url = reverse("admin:servers_server_change", args=[server.id])
    admin_log_sources_url = reverse("admin:servers_serverlogsource_changelist")
    admin_log_sources_url = f"{admin_log_sources_url}?server__id__exact={server.id}"
    context = {
        "server": server,
        "active_tab": "settings",
        "can_shell": user_can_shell(request.user, server, now),
        "can_logs": user_can_logs(request.user, server, now),
        "can_users": can_users,
        "is_server_admin": _is_admin_user(request.user),
        "server_status": _build_server_status(server, now),
        "audit_summary": audit_summary,
        "log_sources": log_sources,
        "admin_server_url": admin_server_url,
        "admin_log_sources_url": admin_log_sources_url,
    }
    return render(request, "servers/settings.html", context)


@login_required(login_url="/accounts/login/")
def server_admin(request, server_id: int):
    now = timezone.now()
    server = _get_server_or_404(request, server_id)
    _require_admin_or_404(request)

    pending_access_requests = list(
        AccessRequest.objects.select_related("requester")
        .filter(server=server, status=AccessRequest.Status.PENDING)
        .order_by("requested_at")
    )
    active_access_requests = list(
        AccessRequest.objects.select_related("requester", "decided_by")
        .filter(server=server, status=AccessRequest.Status.APPROVED)
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .filter(Q(request_shell=True) | Q(request_logs=True) | Q(request_users=True))
        .order_by("requester__username", "-requested_at")
    )
    user_entries: dict[int, dict] = {}
    for access_request in active_access_requests:
        user = access_request.requester
        entry = user_entries.setdefault(
            user.id,
            {
                "user": user,
                "request_count": 0,
                "can_shell": False,
                "can_logs": False,
                "can_users": False,
                "expires_at": access_request.expires_at,
                "sources": set(),
            },
        )
        entry["request_count"] += 1
        entry["can_shell"] = entry["can_shell"] or bool(access_request.request_shell)
        entry["can_logs"] = entry["can_logs"] or bool(access_request.request_logs)
        entry["can_users"] = entry["can_users"] or bool(access_request.request_users)
        current_expires = entry["expires_at"]
        if current_expires is not None and (
            access_request.expires_at is None or access_request.expires_at > current_expires
        ):
            entry["expires_at"] = access_request.expires_at
        entry["sources"].add("Access request")

    users_with_perms = get_users_with_perms(
        server,
        attach_perms=True,
        with_group_users=False,
        only_with_perms_in=["view_server", "shell_server", "change_server"],
    )
    for user, perms in users_with_perms.items():
        entry = user_entries.setdefault(
            user.id,
            {
                "user": user,
                "request_count": 0,
                "can_shell": False,
                "can_logs": False,
                "can_users": False,
                "expires_at": None,
                "sources": set(),
            },
        )
        entry["can_shell"] = entry["can_shell"] or ("shell_server" in perms)
        has_view = "view_server" in perms or "change_server" in perms
        entry["can_logs"] = entry["can_logs"] or has_view
        entry["can_users"] = entry["can_users"] or has_view
        entry["sources"].add("Object permission")

    users_with_access = sorted(
        [
            {
                **entry,
                "source_labels": sorted(entry["sources"]),
            }
            for entry in user_entries.values()
        ],
        key=lambda entry: (entry["user"].username.lower(), entry["user"].id),
    )

    server_accounts = list(
        ServerAccount.objects.select_related("user")
        .filter(server=server)
        .order_by("system_username", "user__username")
    )
    admin_server_url = reverse("admin:servers_server_change", args=[server.id])
    admin_log_sources_url = reverse("admin:servers_serverlogsource_changelist")
    admin_log_sources_url = f"{admin_log_sources_url}?server__id__exact={server.id}"
    context = {
        "server": server,
        "active_tab": "admin",
        "can_shell": user_can_shell(request.user, server, now),
        "can_logs": user_can_logs(request.user, server, now),
        "can_users": user_can_users(request.user, server, now),
        "is_server_admin": True,
        "server_status": _build_server_status(server, now),
        "pending_access_requests": pending_access_requests,
        "users_with_access": users_with_access,
        "server_accounts": server_accounts,
        "admin_server_url": admin_server_url,
        "admin_log_sources_url": admin_log_sources_url,
    }
    return render(request, "servers/server_admin.html", context)


def _get_server_or_404(request, server_id: int) -> Server:
    # Centralized object lookup + permission gate. We raise 404 for both
    # missing objects and permission denials to reduce enumeration signals.
    try:
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise Http404("Server not found")
    if not (request.user.has_perm("servers.view_server", server) or _is_admin_user(request.user)):
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
    rem_seconds = seconds % 60
    if minutes < 60:
        return f"{minutes}m {rem_seconds}s"
    hours = minutes // 60
    rem_minutes = minutes % 60
    if hours < 48:
        return f"{hours}h {rem_minutes}m {rem_seconds}s"
    days = hours // 24
    if days < 14:
        return f"{days}d {hours % 24}h"
    weeks = days // 7
    return f"{weeks}w {days % 7}d"


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


def _parse_filter_datetime(value: str, end_of_day: bool) -> datetime | None:
    if not value:
        return None
    parsed_dt = parse_datetime(value)
    if parsed_dt is not None:
        if timezone.is_naive(parsed_dt):
            return timezone.make_aware(parsed_dt, timezone.get_current_timezone())
        return parsed_dt
    parsed_date = parse_date(value)
    if parsed_date is None:
        return None
    parsed_time = time.max if end_of_day else time.min
    naive = datetime.combine(parsed_date, parsed_time)
    return timezone.make_aware(naive, timezone.get_current_timezone())


def _build_audit_summary(server: Server, now, logs=None) -> dict:
    logs_qs = logs if logs is not None else ServerAuditLog.objects.filter(server=server)
    last_event_at = logs_qs.values_list("event_at", flat=True).first()
    last_ingest_at = logs_qs.values_list("received_at", flat=True).first()
    top_categories = list(
        logs_qs.values("category")
        .annotate(total=Count("id"))
        .order_by("-total", "category")[:5]
    )
    return {
        "total_count": logs_qs.count(),
        "recent_24h_count": logs_qs.filter(event_at__gte=now - timedelta(hours=24)).count(),
        "last_event_at": last_event_at,
        "last_ingest_at": last_ingest_at,
        "top_categories": top_categories,
    }


def _build_audit_chart_context(server: Server) -> dict:
    logs_qs = ServerAuditLog.objects.filter(server=server)
    login_attempt_filter = _login_attempt_filter()
    failed_login_filter = _failed_login_filter()
    success_login_filter = _success_login_filter()
    total_login_attempts = logs_qs.filter(login_attempt_filter).count()
    failed_login_attempts = logs_qs.filter(failed_login_filter).count()
    successful_login_attempts = logs_qs.filter(success_login_filter).count()
    login_chart = _build_chart_payload(
        items=[
            {
                "label": "Total attempts",
                "count": total_login_attempts,
                "color": "#2563eb",
                "drilldown": _build_audit_drilldown_query(login_outcome="attempts"),
            },
            {
                "label": "Failed attempts",
                "count": failed_login_attempts,
                "color": "#e11d48",
                "drilldown": _build_audit_drilldown_query(login_outcome="failed"),
            },
            {
                "label": "Successful attempts",
                "count": successful_login_attempts,
                "color": "#16a34a",
                "drilldown": _build_audit_drilldown_query(login_outcome="success"),
            },
        ],
        max_items=3,
    )
    failure_rate_pct = 0
    if total_login_attempts > 0:
        failure_rate_pct = int(round((failed_login_attempts / total_login_attempts) * 100))

    http_status_counts: Counter[str] = Counter()
    implicit_status_total = 0
    http_logs = logs_qs.filter(
        Q(event_type="http.access")
        | Q(source_name__icontains="nginx")
        | Q(message__icontains="HTTP/")
    ).values_list("fields", "message", "raw")
    for fields, message, raw in http_logs.iterator(chunk_size=500):
        status_code = _extract_http_status_code(fields, message, raw)
        if status_code:
            if status_code == "200" or status_code.startswith("1"):
                implicit_status_total += 1
                continue
            http_status_counts[status_code] += 1
    http_status_chart = _build_chart_payload(
        items=[
            {
                "label": status_code,
                "count": total,
                "color": _http_status_color(status_code),
                "drilldown": _build_audit_drilldown_query(http_status=status_code),
            }
            for status_code, total in sorted(http_status_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        max_items=12,
    )

    failed_source_ip_rows = (
        logs_qs.filter(failed_login_filter)
        .exclude(source_ip__isnull=True)
        .exclude(source_ip="")
        .values("source_ip")
        .annotate(total=Count("id"))
        .order_by("-total", "source_ip")[:8]
    )
    failed_source_ip_chart = _build_chart_payload(
        items=[
            {
                "label": row["source_ip"],
                "count": row["total"],
                "color": "#d97706",
                "drilldown": _build_audit_drilldown_query(login_outcome="failed", source_ip=row["source_ip"]),
            }
            for row in failed_source_ip_rows
        ],
        max_items=8,
    )

    security_event_rows = (
        logs_qs.filter(Q(category__in=["access", "auth"]) | Q(event_type__startswith="ssh."))
        .values("event_type")
        .annotate(total=Count("id"))
        .order_by("-total", "event_type")[:8]
    )
    security_event_chart = _build_chart_payload(
        items=[
            {
                "label": row["event_type"] or "unknown",
                "count": row["total"],
                "color": "#4f46e5",
                "drilldown": _build_audit_drilldown_query(event_type=(row["event_type"] or "unknown")),
            }
            for row in security_event_rows
        ],
        max_items=10,
    )

    return {
        "login_attempts": {
            "total_attempts": total_login_attempts,
            "failed_attempts": failed_login_attempts,
            "successful_attempts": successful_login_attempts,
            "failure_rate_pct": failure_rate_pct,
            "chart": login_chart,
        },
        "http_status_codes": {
            "total": sum(http_status_counts.values()),
            "implicit_total": implicit_status_total,
            "chart": http_status_chart,
        },
        "failed_source_ips": {
            "total": sum(failed_source_ip_chart["values"]),
            "chart": failed_source_ip_chart,
        },
        "security_event_types": {
            "total": sum(security_event_chart["values"]),
            "chart": security_event_chart,
        },
    }


def _extract_http_status_code(fields, message: str, raw: str) -> str:
    if isinstance(fields, dict):
        for key in ("nginx.status", "status", "status_code"):
            candidate = str(fields.get(key, "")).strip()
            if _is_http_status_code(candidate):
                return candidate
    for text in (message, raw):
        if not text:
            continue
        match = HTTP_STATUS_PATTERN.search(text)
        if not match:
            continue
        candidate = match.group(1)
        if _is_http_status_code(candidate):
            return candidate
    return ""


def _is_http_status_code(value: str) -> bool:
    if len(value) != 3 or not value.isdigit():
        return False
    return 100 <= int(value) <= 599


def _http_status_color(status_code: str) -> str:
    if not status_code:
        return "#6b7280"
    family = status_code[0]
    if family == "2":
        return "#16a34a"
    if family == "3":
        return "#2563eb"
    if family == "4":
        return "#d97706"
    if family == "5":
        return "#dc2626"
    return "#6b7280"


def _build_chart_payload(items: list[dict], *, max_items: int) -> dict:
    labels: list[str] = []
    values: list[int] = []
    colors: list[str] = []
    drilldowns: list[str] = []
    for item in items:
        count = int(item.get("count", 0))
        if count <= 0:
            continue
        labels.append(str(item.get("label", "")))
        values.append(count)
        colors.append(str(item.get("color", "#2563eb")))
        drilldowns.append(str(item.get("drilldown", "")))
        if len(labels) >= max_items:
            break
    return {
        "labels": labels,
        "values": values,
        "colors": colors,
        "drilldowns": drilldowns,
    }


def _build_audit_drilldown_query(**filters: str) -> str:
    params: dict[str, str] = {"view": "logs"}
    for key, value in filters.items():
        text = (value or "").strip()
        if not text:
            continue
        params[key] = text
    return urlencode(params)


def _login_attempt_filter() -> Q:
    return (
        Q(event_type__in=SSH_LOGIN_EVENT_TYPES)
        | (Q(category="access") & (Q(message__icontains="Accepted ") | Q(message__icontains="Failed password")))
    )


def _success_login_filter() -> Q:
    return Q(event_type="ssh.login.success") | Q(message__icontains="Accepted ")


def _failed_login_filter() -> Q:
    return (
        Q(event_type="ssh.login.fail")
        | Q(message__icontains="Failed password")
        | Q(message__icontains="authentication failure")
        | Q(message__icontains="invalid user")
    )


def _build_audit_panel_context(request, server: Server, panel_action: str) -> dict:
    logs_qs = ServerAuditLog.objects.filter(server=server)
    all_logs_qs = logs_qs

    category = request.GET.get("category", "").strip()
    event_type = request.GET.get("event_type", "").strip()
    priority = request.GET.get("priority", "").strip()
    source_kind = request.GET.get("source_kind", "").strip()
    source_name = request.GET.get("source_name", "").strip()
    username = request.GET.get("username", "").strip()
    source_ip = request.GET.get("source_ip", "").strip()
    q = request.GET.get("q", "").strip()
    since = request.GET.get("since", "").strip()
    until = request.GET.get("until", "").strip()
    login_outcome = (request.GET.get("login_outcome") or "").strip().lower()
    if login_outcome not in LOGIN_OUTCOME_OPTIONS:
        login_outcome = ""
    http_status = (request.GET.get("http_status") or "").strip()
    if not _is_http_status_code(http_status):
        http_status = ""
    line_limit = _parse_line_limit(request.GET.get("line_limit", ""))

    if category:
        logs_qs = logs_qs.filter(category=category)
    if event_type:
        logs_qs = logs_qs.filter(event_type=event_type)
    if priority:
        logs_qs = logs_qs.filter(priority=priority)
    if source_kind:
        logs_qs = logs_qs.filter(source_kind=source_kind)
    if source_name:
        logs_qs = logs_qs.filter(source_name=source_name)
    if username:
        logs_qs = logs_qs.filter(username__icontains=username)
    if source_ip:
        logs_qs = logs_qs.filter(source_ip__icontains=source_ip)
    if q:
        logs_qs = logs_qs.filter(
            Q(message__icontains=q)
            | Q(raw__icontains=q)
            | Q(principal__icontains=q)
            | Q(session_id__icontains=q)
            | Q(username__icontains=q)
            | Q(event_type__icontains=q)
            | Q(source_name__icontains=q)
        )
    if login_outcome == "attempts":
        logs_qs = logs_qs.filter(_login_attempt_filter())
    elif login_outcome == "success":
        logs_qs = logs_qs.filter(_success_login_filter())
    elif login_outcome == "failed":
        logs_qs = logs_qs.filter(_failed_login_filter())
    if http_status:
        status_token = f" {http_status} "
        quoted_status_token = f'" {http_status} '
        logs_qs = logs_qs.filter(event_type="http.access").filter(
            Q(message__icontains=quoted_status_token)
            | Q(raw__icontains=quoted_status_token)
            | Q(message__icontains=status_token)
            | Q(raw__icontains=status_token)
        )

    since_dt = _parse_filter_datetime(since, end_of_day=False)
    if since_dt:
        logs_qs = logs_qs.filter(event_at__gte=since_dt)
    until_dt = _parse_filter_datetime(until, end_of_day=True)
    if until_dt:
        logs_qs = logs_qs.filter(event_at__lte=until_dt)

    filtered_count = logs_qs.count()
    paginator = Paginator(logs_qs, line_limit)
    page_obj = paginator.get_page(request.GET.get("page") or 1)
    page_logs = list(page_obj.object_list)
    for log in page_logs:
        source_label = (
            (log.source_name or "").strip()
            or (log.unit or "").strip()
            or (log.hostname or "").strip()
            or (log.source_kind or "").strip()
            or "unknown"
        )
        compact_message = ((log.message or "").strip() or (log.raw or "").strip())
        compact_message = " ".join(compact_message.split())
        if not compact_message:
            compact_message = "—"
        if log.priority:
            compact_message = f"[p{log.priority}] {compact_message}"
        log.compact_source = source_label
        log.compact_line = compact_message

    query = request.GET.copy()
    query.pop("page", None)
    query_without_page = query.urlencode()

    event_type_options_qs = all_logs_qs
    if category:
        event_type_options_qs = event_type_options_qs.filter(category=category)

    source_name_options_qs = all_logs_qs
    if source_kind:
        source_name_options_qs = source_name_options_qs.filter(source_kind=source_kind)
    source_name_options = set(source_name_options_qs.order_by().values_list("source_name", flat=True).distinct())
    configured_sources = server.log_sources.filter(enabled=True)
    if source_kind:
        configured_sources = configured_sources.filter(kind=source_kind)
    for configured in configured_sources:
        configured_name = (
            (configured.name or "").strip()
            or (configured.service_unit or "").strip()
            or (configured.file_path or "").strip()
        )
        if configured_name:
            source_name_options.add(configured_name)
    source_kind_options = set(all_logs_qs.order_by().values_list("source_kind", flat=True).distinct())
    source_kind_options.update(server.log_sources.filter(enabled=True).order_by().values_list("kind", flat=True))

    filters_active = any(
        [
            category,
            event_type,
            priority,
            source_kind,
            source_name,
            username,
            source_ip,
            q,
            since,
            until,
            login_outcome,
            http_status,
        ]
    )
    reset_href = f"{panel_action}?line_limit={line_limit}"

    return {
        "logs": page_logs,
        "page_obj": page_obj,
        "query_without_page": query_without_page,
        "panel_action": panel_action,
        "line_limit": line_limit,
        "line_limit_options": AUDIT_LINE_LIMIT_OPTIONS,
        "filters_expanded": filters_active,
        "reset_href": reset_href,
        "filtered_count": filtered_count,
        "filter_values": {
            "category": category,
            "event_type": event_type,
            "priority": priority,
            "source_kind": source_kind,
            "source_name": source_name,
            "username": username,
            "source_ip": source_ip,
            "q": q,
            "since": since,
            "until": until,
            "login_outcome": login_outcome,
            "http_status": http_status,
            "line_limit": str(line_limit),
        },
        "filter_options": {
            "categories": sorted(all_logs_qs.order_by().values_list("category", flat=True).distinct()),
            "event_types": sorted(event_type_options_qs.order_by().values_list("event_type", flat=True).distinct()),
            "priorities": sorted(all_logs_qs.order_by().values_list("priority", flat=True).distinct()),
            "source_kinds": sorted(source_kind_options),
            "source_names": sorted(source_name_options),
        },
    }


def _parse_line_limit(raw_value) -> int:
    try:
        parsed = int(str(raw_value).strip())
    except (TypeError, ValueError):
        return DEFAULT_AUDIT_LINE_LIMIT
    if parsed in AUDIT_LINE_LIMIT_OPTIONS:
        return parsed
    return DEFAULT_AUDIT_LINE_LIMIT


def _admin_next_redirect_target(request) -> str:
    target = (request.POST.get("next") or "").strip()
    if target.startswith("/"):
        return target
    return reverse("servers:admin_dashboard")


def _next_redirect_target(request, server_id: int) -> str:
    target = (request.POST.get("next") or "").strip()
    if target.startswith("/"):
        return target
    return reverse("servers:server_admin", args=[server_id])

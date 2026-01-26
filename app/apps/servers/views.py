from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user

from apps.access.models import AccessRequest
from apps.servers.models import Server


@login_required(login_url="/accounts/login/")
def dashboard(request):
    now = timezone.now()
    if request.user.has_perm("servers.view_server"):
        server_qs = Server.objects.all()
    else:
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

    servers = [
        {
            "server": server,
            "expires_at": expires_map.get(server.id),
            "last_accessed": None,
        }
        for server in server_qs
    ]

    context = {
        "servers": servers,
    }
    return render(request, "servers/dashboard.html", context)


@login_required(login_url="/accounts/login/")
def detail(request, server_id: int):
    now = timezone.now()
    try:
        server = Server.objects.get(id=server_id)
    except Server.DoesNotExist:
        raise Http404("Server not found")
    if not request.user.has_perm("servers.view_server", server) and not request.user.has_perm(
        "servers.view_server"
    ):
        raise Http404("Server not found")

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

    context = {
        "server": server,
        "expires_at": access.expires_at if access else None,
        "last_accessed": None,
    }
    return render(request, "servers/detail.html", context)

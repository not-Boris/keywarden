from __future__ import annotations

from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import Http404
from django.shortcuts import render
from django.utils import timezone

from apps.access.models import AccessRequest


@login_required(login_url="/accounts/login/")
def dashboard(request):
    now = timezone.now()
    access_qs = (
        AccessRequest.objects.select_related("server")
        .filter(
            requester=request.user,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-requested_at")
    )

    seen = set()
    servers = []
    for access in access_qs:
        if access.server_id in seen:
            continue
        seen.add(access.server_id)
        servers.append(
            {
                "server": access.server,
                "expires_at": access.expires_at,
                "last_accessed": None,
            }
        )

    context = {
        "servers": servers,
    }
    return render(request, "servers/dashboard.html", context)


@login_required(login_url="/accounts/login/")
def detail(request, server_id: int):
    now = timezone.now()
    access = (
        AccessRequest.objects.select_related("server")
        .filter(
            requester=request.user,
            server_id=server_id,
            status=AccessRequest.Status.APPROVED,
        )
        .filter(Q(expires_at__isnull=True) | Q(expires_at__gt=now))
        .order_by("-requested_at")
        .first()
    )
    if not access:
        raise Http404("Server not found")

    context = {
        "server": access.server,
        "expires_at": access.expires_at,
        "last_accessed": None,
    }
    return render(request, "servers/detail.html", context)

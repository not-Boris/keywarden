from django.contrib import admin
from guardian.admin import GuardedModelAdmin

from .models import AccessRequest


@admin.register(AccessRequest)
class AccessRequestAdmin(GuardedModelAdmin):
    list_display = (
        "id",
        "requester",
        "server",
        "status",
        "requested_at",
        "expires_at",
        "decided_by",
    )
    list_filter = ("status", "server")
    search_fields = ("requester__username", "requester__email", "server__display_name")
    ordering = ("-requested_at",)

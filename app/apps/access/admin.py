from django.contrib import admin

from .models import AccessRequest


@admin.register(AccessRequest)
class AccessRequestAdmin(admin.ModelAdmin):
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

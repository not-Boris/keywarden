from django.contrib import admin
from django.urls import reverse
from django.utils import timezone
from django.utils.html import format_html
try:
    from unfold.contrib.guardian.admin import GuardedModelAdmin
except ImportError:  # Fallback for older Unfold builds without guardian admin shim.
    from guardian.admin import GuardedModelAdmin as GuardianGuardedModelAdmin
    from unfold.admin import ModelAdmin as UnfoldModelAdmin

    class GuardedModelAdmin(GuardianGuardedModelAdmin, UnfoldModelAdmin):
        pass

from .models import AccessRequest


@admin.register(AccessRequest)
class AccessRequestAdmin(GuardedModelAdmin):
    autocomplete_fields = ("requester", "server", "decided_by")
    list_display = (
        "id",
        "requester",
        "server",
        "status",
        "request_shell",
        "request_logs",
        "request_users",
        "requested_duration_hours",
        "requested_server_username",
        "requested_at",
        "expires_at",
        "decided_by",
        "delete_link",
    )
    list_filter = ("status", "server")
    search_fields = ("requester__username", "requester__email", "server__display_name")
    ordering = ("-requested_at",)
    compressed_fields = True
    actions_on_top = True
    actions_on_bottom = True
    def get_readonly_fields(self, request, obj=None):
        readonly = ["requested_at"]
        if obj:
            readonly.extend(["decided_at", "decided_by"])
        return readonly

    def get_fieldsets(self, request, obj=None):
        if obj is None:
            return (
                (
                    "Request",
                    {
                        "fields": (
                            "requester",
                            "server",
                            "status",
                            "reason",
                            "request_shell",
                            "request_logs",
                            "request_users",
                            "requested_duration_hours",
                            "requested_server_username",
                            "expires_at",
                        )
                    },
                ),
            )
        return (
            (
                "Request",
                {
                    "fields": (
                        "requester",
                        "server",
                        "status",
                        "reason",
                        "request_shell",
                        "request_logs",
                        "request_users",
                        "requested_duration_hours",
                        "requested_server_username",
                        "expires_at",
                    )
                },
            ),
            (
                "Decision",
                {
                    "fields": (
                        "decided_at",
                        "decided_by",
                    )
                },
            ),
        )

    def save_model(self, request, obj, form, change) -> None:
        if obj.status in {
            AccessRequest.Status.APPROVED,
            AccessRequest.Status.DENIED,
            AccessRequest.Status.REVOKED,
            AccessRequest.Status.CANCELLED,
        }:
            if not obj.decided_at:
                obj.decided_at = timezone.now()
            if not obj.decided_by_id and request.user and request.user.is_authenticated:
                obj.decided_by = request.user
        super().save_model(request, obj, form, change)

    def delete_link(self, obj: AccessRequest):
        url = reverse("admin:access_accessrequest_delete", args=[obj.pk])
        return format_html('<a class="text-red-600" href="{}">Delete</a>', url)

    delete_link.short_description = "Delete"

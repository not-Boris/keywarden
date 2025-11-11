from django.contrib import admin
from unfold.admin import ModelAdmin
from unfold.decorators import action  # type: ignore

from .models import AuditEventType, AuditLog


@admin.register(AuditEventType)
class AuditEventTypeAdmin(ModelAdmin):
    list_display = ("key", "title", "default_severity", "created_at")
    search_fields = ("key", "title", "description")
    list_filter = ("default_severity",)
    ordering = ("key",)
    compressed_fields = True


@admin.register(AuditLog)
class AuditLogAdmin(ModelAdmin):
    date_hierarchy = "created_at"
    list_display = (
        "created_at",
        "severity",
        "event_type",
        "actor",
        "object_repr",
        "source",
        "ip_address",
    )
    list_filter = (
        "severity",
        "source",
        "event_type",
        ("actor", admin.RelatedOnlyFieldListFilter),
        "created_at",
    )
    search_fields = (
        "message",
        "object_repr",
        "ip_address",
        "user_agent",
        "request_id",
        "metadata",
        "actor__username",
        "actor__email",
    )
    readonly_fields = (
        "created_at",
        "actor",
        "event_type",
        "message",
        "severity",
        "source",
        "target_content_type",
        "target_object_id",
        "object_repr",
        "ip_address",
        "user_agent",
        "request_id",
        "metadata",
    )
    compressed_fields = True
    list_per_page = 50

    fieldsets = (
        (
            None,
            {
                "fields": (
                    "created_at",
                    "event_type",
                    "severity",
                    "message",
                    "source",
                )
            },
        ),
        (
            "Actor",
            {"fields": ("actor", "ip_address", "user_agent", "request_id")},
        ),
        (
            "Target",
            {"fields": ("target_content_type", "target_object_id", "object_repr")},
        ),
        (
            "Metadata",
            {"fields": ("metadata",)},
        ),
    )



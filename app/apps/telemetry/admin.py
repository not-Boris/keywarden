from django.contrib import admin

from .models import TelemetryEvent


@admin.register(TelemetryEvent)
class TelemetryEventAdmin(admin.ModelAdmin):
    list_display = ("id", "event_type", "server", "user", "success", "source", "created_at")
    list_filter = ("success", "source", "event_type")
    search_fields = ("event_type", "message", "server__display_name", "user__username")
    ordering = ("-created_at",)

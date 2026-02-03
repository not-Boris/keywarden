import json

from django import forms
from django.contrib import admin
from unfold.admin import ModelAdmin

from .matching import list_api_endpoint_suggestions, list_websocket_endpoint_suggestions
from .models import AuditEventType, AuditLog


class AuditEventTypeAdminForm(forms.ModelForm):
    endpoints_text = forms.CharField(
        required=False,
        widget=forms.Textarea(
            attrs={
                "rows": 8,
                "placeholder": "/api/v1/servers/\nGET /api/v1/servers/<int:server_id>/\n/ws/servers/*/shell/",
            }
        ),
        help_text=(
            "One endpoint pattern per line. Supports '*' wildcards and optional METHOD prefixes "
            "like 'GET /api/v1/servers/*'."
        ),
        label="Endpoint patterns",
    )
    ip_whitelist_text = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "10.0.0.1\n192.168.1.0/24"}),
        help_text="One IP address or CIDR range per line.",
        label="IP whitelist entries",
    )
    ip_blacklist_text = forms.CharField(
        required=False,
        widget=forms.Textarea(attrs={"rows": 4, "placeholder": "203.0.113.10\n198.51.100.0/24"}),
        help_text="One IP address or CIDR range per line.",
        label="IP blacklist entries",
    )

    class Meta:
        model = AuditEventType
        fields = (
            "key",
            "title",
            "description",
            "kind",
            "default_severity",
            "endpoints_text",
            "ip_whitelist_enabled",
            "ip_whitelist_text",
            "ip_blacklist_enabled",
            "ip_blacklist_text",
        )

    class Media:
        js = ("audit/eventtype_form.js",)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        instance = kwargs.get("instance") or getattr(self, "instance", None)
        if instance and instance.pk:
            self.fields["endpoints_text"].initial = "\n".join(instance.endpoints or [])
            self.fields["ip_whitelist_text"].initial = "\n".join(instance.ip_whitelist or [])
            self.fields["ip_blacklist_text"].initial = "\n".join(instance.ip_blacklist or [])
        self.fields["endpoints_text"].widget.attrs["data-api-suggestions"] = json.dumps(
            list_api_endpoint_suggestions()
        )
        self.fields["endpoints_text"].widget.attrs["data-ws-suggestions"] = json.dumps(
            list_websocket_endpoint_suggestions()
        )

    def _lines_to_list(self, value: str) -> list[str]:
        results: list[str] = []
        for line in (value or "").splitlines():
            candidate = line.strip()
            if candidate:
                results.append(candidate)
        return results

    def clean_endpoints_text(self) -> str:
        value = self.cleaned_data.get("endpoints_text", "")
        # Normalize whitespace but keep the raw text for display.
        lines = self._lines_to_list(value)
        return "\n".join(lines)

    def save(self, commit: bool = True):
        instance: AuditEventType = super().save(commit=False)
        endpoints_text = self.cleaned_data.get("endpoints_text", "")
        whitelist_text = self.cleaned_data.get("ip_whitelist_text", "")
        blacklist_text = self.cleaned_data.get("ip_blacklist_text", "")
        instance.endpoints = self._lines_to_list(endpoints_text)
        instance.ip_whitelist = self._lines_to_list(whitelist_text)
        instance.ip_blacklist = self._lines_to_list(blacklist_text)
        if commit:
            instance.save()
        return instance


@admin.register(AuditEventType)
class AuditEventTypeAdmin(ModelAdmin):
    form = AuditEventTypeAdminForm
    list_display = ("key", "title", "kind", "default_severity", "created_at")
    search_fields = ("key", "title", "description", "endpoints")
    list_filter = ("kind", "default_severity", "ip_whitelist_enabled", "ip_blacklist_enabled")
    ordering = ("key",)
    compressed_fields = True
    fieldsets = (
        (
            "Event Type",
            {
                "fields": (
                    "key",
                    "title",
                    "description",
                    "kind",
                    "default_severity",
                )
            },
        ),
        (
            "Endpoints",
            {
                "fields": ("endpoints_text",),
                "description": "Only matching endpoints will create audit events.",
            },
        ),
        (
            "IP Controls",
            {
                "fields": (
                    "ip_whitelist_enabled",
                    "ip_whitelist_text",
                    "ip_blacklist_enabled",
                    "ip_blacklist_text",
                ),
            },
        ),
    )


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

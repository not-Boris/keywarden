from django.contrib import admin
from django.utils.html import format_html
try:
    from unfold.contrib.guardian.admin import GuardedModelAdmin
except ImportError:  # Fallback for older Unfold builds without guardian admin shim.
    from guardian.admin import GuardedModelAdmin as GuardianGuardedModelAdmin
    from unfold.admin import ModelAdmin as UnfoldModelAdmin

    class GuardedModelAdmin(GuardianGuardedModelAdmin, UnfoldModelAdmin):
        pass

from .models import AgentCertificateAuthority, EnrollmentToken, Server, ServerAuditLog, ServerLogSource


class ServerLogSourceInline(admin.TabularInline):
    model = ServerLogSource
    extra = 0
    fields = (
        "enabled",
        "kind",
        "name",
        "service_unit",
        "file_path",
        "parser",
        "include_matches",
        "exclude_matches",
        "category_override",
        "event_type_override",
    )
    ordering = ("kind", "name", "id")


@admin.register(Server)
class ServerAdmin(GuardedModelAdmin):
    list_display = ("avatar", "display_name", "hostname", "ipv4", "ipv6", "agent_enrolled_at", "created_at")
    list_display_links = ("display_name",)
    search_fields = ("display_name", "hostname", "ipv4", "ipv6")
    list_filter = ("created_at",)
    readonly_fields = ("created_at", "updated_at", "agent_enrolled_at")
    fields = (
        "display_name",
        "hostname",
        "ipv4",
        "ipv6",
        "image",
        "agent_enrolled_at",
        "created_at",
        "updated_at",
    )
    inlines = (ServerLogSourceInline,)

    def avatar(self, obj: Server):
        if obj.image_url:
            return format_html(
                '<img src="{}" alt="{}" style="width:28px;height:28px;border-radius:6px;object-fit:cover;" />',
                obj.image_url,
                obj.display_name,
            )
        initial = obj.initial
        return format_html(
            '<div style="width:28px;height:28px;border-radius:6px;background:#7C3AED;color:white;display:flex;align-items:center;justify-content:center;font-weight:600;">{}</div>',
            initial,
        )
    avatar.short_description = ""


@admin.register(EnrollmentToken)
class EnrollmentTokenAdmin(admin.ModelAdmin):
    list_display = ("token", "created_at", "expires_at", "used_at", "server")
    list_filter = ("created_at", "used_at")
    search_fields = ("token", "server__display_name", "server__hostname")
    readonly_fields = ("token", "created_at", "used_at", "server", "created_by")
    fields = ("token", "expires_at", "created_by", "created_at", "used_at", "server")

    def save_model(self, request, obj, form, change) -> None:
        if not obj.pk:
            obj.ensure_token()
            if request.user and request.user.is_authenticated and not obj.created_by_id:
                obj.created_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(AgentCertificateAuthority)
class AgentCertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_at", "revoked_at")
    list_filter = ("is_active", "created_at", "revoked_at")
    search_fields = ("name", "fingerprint")
    readonly_fields = ("cert_pem", "fingerprint", "serial", "created_at", "revoked_at", "created_by")
    fields = (
        "name",
        "is_active",
        "cert_pem",
        "fingerprint",
        "serial",
        "created_by",
        "created_at",
        "revoked_at",
    )
    actions = ["revoke_selected"]

    def save_model(self, request, obj, form, change) -> None:
        if request.user and request.user.is_authenticated and not obj.created_by_id:
            obj.created_by = request.user
        obj.ensure_material()
        if obj.is_active:
            AgentCertificateAuthority.objects.exclude(pk=obj.pk).update(is_active=False)
        super().save_model(request, obj, form, change)

    @admin.action(description="Revoke selected CAs")
    def revoke_selected(self, request, queryset):
        for ca in queryset:
            ca.revoke()
            ca.save(update_fields=["is_active", "revoked_at"])


@admin.register(ServerAuditLog)
class ServerAuditLogAdmin(admin.ModelAdmin):
    list_display = (
        "event_at",
        "server",
        "source_kind",
        "source_name",
        "category",
        "event_type",
        "username",
        "source_ip",
        "priority",
    )
    list_filter = ("source_kind", "category", "event_type", "priority", "server")
    search_fields = ("message", "raw", "source_name", "username", "principal", "source_ip", "session_id")
    readonly_fields = (
        "server",
        "event_at",
        "received_at",
        "source_kind",
        "source_name",
        "category",
        "event_type",
        "unit",
        "priority",
        "hostname",
        "username",
        "principal",
        "source_ip",
        "session_id",
        "message",
        "raw",
        "fields",
    )
    ordering = ("-event_at", "-id")


@admin.register(ServerLogSource)
class ServerLogSourceAdmin(admin.ModelAdmin):
    list_display = (
        "server",
        "enabled",
        "kind",
        "name",
        "service_unit",
        "file_path",
        "parser",
        "category_override",
        "event_type_override",
    )
    list_filter = ("enabled", "kind", "server")
    search_fields = (
        "name",
        "service_unit",
        "file_path",
        "parser",
        "category_override",
        "event_type_override",
    )

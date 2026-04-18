from django.contrib import admin
from django.conf import settings
from django.utils.html import format_html

try:
    from unfold.admin import ModelAdmin as UnfoldModelAdmin
except ImportError:
    UnfoldModelAdmin = admin.ModelAdmin

try:
    from unfold.contrib.guardian.admin import GuardedModelAdmin
except ImportError:  # Fallback for older Unfold builds without guardian admin shim.
    from guardian.admin import GuardedModelAdmin as GuardianGuardedModelAdmin

    class GuardedModelAdmin(GuardianGuardedModelAdmin, UnfoldModelAdmin):
        pass

from apps.access.models import AccessRequest

from .models import (
    AgentCertificateAuthority,
    EnrollmentToken,
    Server,
    ServerAccount,
    ServerAuditLog,
    ServerLogSource,
)


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

    def _large_delete_preview_threshold(self) -> int:
        value = getattr(settings, "KEYWARDEN_ADMIN_DELETE_PREVIEW_MAX_ITEMS", 5000)
        try:
            threshold = int(value)
        except (TypeError, ValueError):
            threshold = 5000
        return max(threshold, 1)

    def _related_delete_counts(self, server_ids: list[int]) -> dict[str, int]:
        return {
            ServerAuditLog._meta.verbose_name_plural: ServerAuditLog.objects.filter(server_id__in=server_ids).count(),
            ServerAccount._meta.verbose_name_plural: ServerAccount.objects.filter(server_id__in=server_ids).count(),
            ServerLogSource._meta.verbose_name_plural: ServerLogSource.objects.filter(server_id__in=server_ids).count(),
            AccessRequest._meta.verbose_name_plural: AccessRequest.objects.filter(server_id__in=server_ids).count(),
        }

    def get_deleted_objects(self, objs, request):
        # Django's default nested object preview scales poorly for very large
        # cascades (for example, many ServerAuditLog rows) and can cause
        # worker timeouts/OOM during delete confirmation rendering.
        if not request.user.is_superuser:
            return super().get_deleted_objects(objs, request)

        server_ids = list(objs.values_list("id", flat=True))
        if not server_ids:
            return super().get_deleted_objects(objs, request)

        related_counts = self._related_delete_counts(server_ids)
        total_related = sum(related_counts.values())
        if total_related < self._large_delete_preview_threshold():
            return super().get_deleted_objects(objs, request)

        model_count = {
            self.model._meta.verbose_name_plural: len(server_ids),
        }
        deleted_objects = [f"{len(server_ids)} {self.model._meta.verbose_name_plural}"]
        for label, count in related_counts.items():
            if count:
                model_count[label] = count
                deleted_objects.append(f"{count} {label}")
        deleted_objects.append(
            "Large cascade detected. Related objects are summarized here to keep delete confirmation responsive."
        )
        return deleted_objects, model_count, set(), []

    def _purge_server_audit_logs(self, server_ids: list[int]) -> None:
        if not server_ids:
            return
        ServerAuditLog.objects.filter(server_id__in=server_ids).delete()

    def delete_model(self, request, obj) -> None:
        self._purge_server_audit_logs([obj.id])
        super().delete_model(request, obj)

    def delete_queryset(self, request, queryset) -> None:
        self._purge_server_audit_logs(list(queryset.values_list("id", flat=True)))
        super().delete_queryset(request, queryset)

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
class EnrollmentTokenAdmin(UnfoldModelAdmin):
    list_display = ("token", "created_at", "expires_at", "used_at", "server")
    list_filter = ("created_at", "used_at")
    search_fields = ("token", "server__display_name", "server__hostname")
    readonly_fields = ("token", "created_at", "used_at", "server", "created_by")
    fields = ("token", "expires_at", "created_by", "created_at", "used_at", "server")

    def get_fields(self, request, obj=None):
        # Keep the add form minimal and deterministic in Unfold: token and
        # metadata are generated server-side and shown on the change view.
        if obj is None:
            return ("expires_at",)
        return self.fields

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

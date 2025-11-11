from django.contrib import admin
from django.utils.html import format_html
from .models import Server


@admin.register(Server)
class ServerAdmin(admin.ModelAdmin):
    list_display = ("avatar", "display_name", "hostname", "ipv4", "ipv6", "created_at")
    list_display_links = ("display_name",)
    search_fields = ("display_name", "hostname", "ipv4", "ipv6")
    list_filter = ("created_at",)
    readonly_fields = ("created_at", "updated_at")
    fields = ("display_name", "hostname", "ipv4", "ipv6", "image", "created_at", "updated_at")

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



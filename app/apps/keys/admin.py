from django.contrib import admin

from .models import SSHKey


@admin.register(SSHKey)
class SSHKeyAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "name", "key_type", "fingerprint", "is_active", "created_at")
    list_filter = ("is_active", "key_type")
    search_fields = ("name", "user__username", "user__email", "fingerprint")
    ordering = ("-created_at",)

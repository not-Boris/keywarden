from django.contrib import admin
try:
    from unfold.contrib.guardian.admin import GuardedModelAdmin
except ImportError:  # Fallback for older Unfold builds without guardian admin shim.
    from guardian.admin import GuardedModelAdmin as GuardianGuardedModelAdmin
    from unfold.admin import ModelAdmin as UnfoldModelAdmin

    class GuardedModelAdmin(GuardianGuardedModelAdmin, UnfoldModelAdmin):
        pass

from .models import SSHKey


@admin.register(SSHKey)
class SSHKeyAdmin(GuardedModelAdmin):
    list_display = ("id", "user", "name", "key_type", "fingerprint", "is_active", "created_at")
    list_filter = ("is_active", "key_type")
    search_fields = ("name", "user__username", "user__email", "fingerprint")
    ordering = ("-created_at",)

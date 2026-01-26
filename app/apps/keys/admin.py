from django.contrib import admin
try:
    from unfold.contrib.guardian.admin import GuardedModelAdmin
except ImportError:  # Fallback for older Unfold builds without guardian admin shim.
    from guardian.admin import GuardedModelAdmin as GuardianGuardedModelAdmin
    from unfold.admin import ModelAdmin as UnfoldModelAdmin

    class GuardedModelAdmin(GuardianGuardedModelAdmin, UnfoldModelAdmin):
        pass

from .models import SSHCertificate, SSHCertificateAuthority, SSHKey


@admin.register(SSHKey)
class SSHKeyAdmin(GuardedModelAdmin):
    list_display = ("id", "user", "name", "key_type", "fingerprint", "is_active", "created_at")
    list_filter = ("is_active", "key_type")
    search_fields = ("name", "user__username", "user__email", "fingerprint")
    ordering = ("-created_at",)


@admin.register(SSHCertificateAuthority)
class SSHCertificateAuthorityAdmin(admin.ModelAdmin):
    list_display = ("name", "fingerprint", "is_active", "created_at", "revoked_at")
    list_filter = ("is_active",)
    search_fields = ("name", "fingerprint")
    readonly_fields = ("created_at", "revoked_at", "fingerprint", "public_key", "private_key")
    ordering = ("-created_at",)


@admin.register(SSHCertificate)
class SSHCertificateAdmin(admin.ModelAdmin):
    list_display = ("id", "user", "key", "serial", "is_active", "valid_before", "created_at")
    list_filter = ("is_active",)
    search_fields = ("user__username", "user__email", "serial")
    readonly_fields = ("created_at", "revoked_at", "certificate")
    ordering = ("-created_at",)

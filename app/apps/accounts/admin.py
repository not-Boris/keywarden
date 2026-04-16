from django import forms
from django.contrib import admin
from django.utils import timezone
from unfold.admin import ModelAdmin

from .models import ErasureRequest, ExternalIdentity, NativeAccountSecurity


class ErasureRequestAdminForm(forms.ModelForm):
    class Meta:
        model = ErasureRequest
        fields = "__all__"

    def clean(self):
        cleaned = super().clean()
        status = cleaned.get("status")
        decision_reason = (cleaned.get("decision_reason") or "").strip()
        if status in {ErasureRequest.Status.DENIED, ErasureRequest.Status.PROCESSED} and not decision_reason:
            raise forms.ValidationError("Decision reason is required for denied or processed requests.")
        return cleaned


@admin.register(ErasureRequest)
class ErasureRequestAdmin(ModelAdmin):
    form = ErasureRequestAdminForm
    list_display = ("id", "user", "status", "requested_at", "decided_at", "processed_at")
    list_filter = ("status", "requested_at", "processed_at")
    search_fields = ("user__username", "user__email")
    readonly_fields = ("requested_at", "decided_at", "processed_at", "decided_by", "processed_by")
    fieldsets = (
        (
            "Request",
            {
                "fields": ("user", "reason", "status", "requested_at"),
            },
        ),
        (
            "Decision",
            {
                "fields": ("decision_reason", "decided_by", "decided_at"),
            },
        ),
        (
            "Processing",
            {
                "fields": ("processed_by", "processed_at"),
            },
        ),
    )

    def save_model(self, request, obj, form, change) -> None:
        if obj.status == ErasureRequest.Status.PROCESSED:
            obj.process(request.user, decision_reason=obj.decision_reason)
            return
        if obj.status == ErasureRequest.Status.DENIED and not obj.decided_at:
            obj.decided_at = timezone.now()
            obj.decided_by = request.user
        super().save_model(request, obj, form, change)


@admin.register(ExternalIdentity)
class ExternalIdentityAdmin(ModelAdmin):
    list_display = (
        "id",
        "user",
        "provider_type",
        "provider_id",
        "subject",
        "email_at_link",
        "last_login_at",
    )
    list_filter = ("provider_type", "provider_id")
    search_fields = ("user__username", "user__email", "subject", "provider_id", "issuer")
    readonly_fields = (
        "user",
        "provider_type",
        "provider_id",
        "issuer",
        "subject",
        "email_at_link",
        "details",
        "created_at",
        "updated_at",
        "last_login_at",
    )

    def has_add_permission(self, request) -> bool:
        return False

    def has_delete_permission(self, request, obj=None) -> bool:
        return False


@admin.register(NativeAccountSecurity)
class NativeAccountSecurityAdmin(ModelAdmin):
    list_display = (
        "user",
        "email_verified",
        "email_verified_at",
        "verification_email_sent_at",
        "updated_at",
    )
    list_filter = ("email_verified",)
    search_fields = ("user__username", "user__email")
    readonly_fields = ("user", "email_verified_at", "verification_email_sent_at", "updated_at")

    def has_add_permission(self, request) -> bool:
        return False

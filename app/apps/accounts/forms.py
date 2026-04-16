from django import forms
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import PasswordResetForm, SetPasswordForm

from .models import ExternalIdentity


class NativePasswordResetForm(PasswordResetForm):
    """Password reset form that excludes SSO-linked accounts."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields["email"].widget.attrs.update(
            {
                "class": "block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500",
                "placeholder": "you@example.com",
            }
        )

    def get_users(self, email):
        UserModel = get_user_model()
        email_field_name = UserModel.get_email_field_name()
        users = UserModel._default_manager.filter(
            **{
                f"{email_field_name}__iexact": email,
                "is_active": True,
            }
        )
        for user in users:
            email_value = getattr(user, email_field_name, "") or ""
            if not user.has_usable_password():
                continue
            if ExternalIdentity.objects.filter(user=user).exists():
                continue
            if email.lower() != email_value.lower():
                continue
            yield user


class StyledSetPasswordForm(SetPasswordForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        field_attrs = {
            "class": "block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500",
        }
        self.fields["new_password1"].widget.attrs.update(field_attrs)
        self.fields["new_password2"].widget.attrs.update(field_attrs)


class ErasureRequestForm(forms.Form):
    reason = forms.CharField(
        label="Reason for erasure request",
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "Explain why you are requesting data erasure.",
                "class": "block w-full resize-y rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500",
            }
        ),
        min_length=10,
        max_length=2000,
    )


class SSHKeyForm(forms.Form):
    name = forms.CharField(
        label="Key Name",
        max_length=128,
        widget=forms.TextInput(
            attrs={
                "placeholder": "Device Name",
                "class": "block w-full rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500",
            }
        ),
    )
    public_key = forms.CharField(
        label="SSH Public Key",
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "ssh-ed25519 AAAaBBbBcCcc111122223333... user@host",
                "class": "block w-full resize-y rounded-lg border border-gray-300 bg-gray-50 p-2.5 text-sm text-gray-900 focus:border-blue-500 focus:ring-blue-500",
            }
        ),
    )

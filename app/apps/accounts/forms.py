from django import forms


class ErasureRequestForm(forms.Form):
    reason = forms.CharField(
        label="Reason for erasure request",
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "Explain why you are requesting data erasure.",
                "class": "w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-purple-600 focus:outline-none focus:ring-1 focus:ring-purple-600",
            }
        ),
        min_length=10,
        max_length=2000,
    )


class SSHKeyForm(forms.Form):
    name = forms.CharField(
        label="Key name",
        max_length=128,
        widget=forms.TextInput(
            attrs={
                "placeholder": "MacBook Pro",
                "class": "w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-purple-600 focus:outline-none focus:ring-1 focus:ring-purple-600",
            }
        ),
    )
    public_key = forms.CharField(
        label="SSH public key",
        widget=forms.Textarea(
            attrs={
                "rows": 4,
                "placeholder": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB... you@host",
                "class": "w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm text-gray-900 shadow-sm focus:border-purple-600 focus:outline-none focus:ring-1 focus:ring-purple-600",
            }
        ),
    )

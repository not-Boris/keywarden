from django import forms


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

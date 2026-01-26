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

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.db.models.signals import pre_save
from django.dispatch import receiver


@receiver(pre_save, sender=get_user_model())
def enforce_immutable_email(sender, instance, **kwargs) -> None:
    if not getattr(instance, "pk", None):
        return
    if getattr(instance, "_allow_email_update", False):
        return

    current = sender.objects.filter(pk=instance.pk).values("email").first()
    if not current:
        return

    old_email = (current.get("email") or "").strip().lower()
    new_email = (getattr(instance, "email", "") or "").strip().lower()
    if old_email == new_email:
        return

    raise ValidationError({"email": "Email is immutable and cannot be changed once set."})

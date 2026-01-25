from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver

from apps.core.rbac import assign_default_object_permissions
from .models import Server


@receiver(post_save, sender=Server)
def assign_server_perms(sender, instance: Server, created: bool, **kwargs) -> None:
    if not created:
        return
    assign_default_object_permissions(instance)

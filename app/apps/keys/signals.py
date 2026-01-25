from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm

from apps.core.rbac import assign_default_object_permissions
from .models import SSHKey


@receiver(post_save, sender=SSHKey)
def assign_ssh_key_perms(sender, instance: SSHKey, created: bool, **kwargs) -> None:
    if not created:
        return
    if instance.user_id:
        user = instance.user
        for perm in ("keys.view_sshkey", "keys.change_sshkey", "keys.delete_sshkey"):
            assign_perm(perm, user, instance)
    assign_default_object_permissions(instance)

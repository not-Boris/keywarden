from __future__ import annotations

from django.db.models.signals import post_save
from django.dispatch import receiver
from guardian.shortcuts import assign_perm

from apps.core.rbac import assign_default_object_permissions
from .models import AccessRequest
from .permissions import sync_server_view_perm


@receiver(post_save, sender=AccessRequest)
def assign_access_request_perms(sender, instance: AccessRequest, created: bool, **kwargs) -> None:
    if not created:
        sync_server_view_perm(instance)
        return
    if instance.requester_id:
        user = instance.requester
        for perm in (
            "access.view_accessrequest",
            "access.change_accessrequest",
            "access.delete_accessrequest",
        ):
            assign_perm(perm, user, instance)
    assign_default_object_permissions(instance)
    sync_server_view_perm(instance)

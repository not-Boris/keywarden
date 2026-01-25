from django.core.management.base import BaseCommand

from guardian.shortcuts import assign_perm

from apps.access.models import AccessRequest
from apps.core.rbac import assign_default_object_permissions
from apps.keys.models import SSHKey
from apps.servers.models import Server


class Command(BaseCommand):
    help = "Backfill guardian object permissions for access requests and SSH keys."

    def handle(self, *args, **options):
        access_count = 0
        for access_request in AccessRequest.objects.select_related("requester"):
            if not access_request.requester_id:
                assign_default_object_permissions(access_request)
            else:
                for perm in (
                    "access.view_accessrequest",
                    "access.change_accessrequest",
                    "access.delete_accessrequest",
                ):
                    assign_perm(perm, access_request.requester, access_request)
                assign_default_object_permissions(access_request)
            access_count += 1

        key_count = 0
        for key in SSHKey.objects.select_related("user"):
            if not key.user_id:
                assign_default_object_permissions(key)
            else:
                for perm in ("keys.view_sshkey", "keys.change_sshkey", "keys.delete_sshkey"):
                    assign_perm(perm, key.user, key)
                assign_default_object_permissions(key)
            key_count += 1

        server_count = 0
        for server in Server.objects.all():
            assign_default_object_permissions(server)
            server_count += 1

        self.stdout.write(
            self.style.SUCCESS(
                "Synced object permissions for "
                f"{access_count} access requests, "
                f"{key_count} SSH keys, "
                f"and {server_count} servers."
            )
        )

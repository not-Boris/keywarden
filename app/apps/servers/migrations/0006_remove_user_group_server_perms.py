from django.db import migrations


def remove_user_group_server_perms(apps, schema_editor):
    Group = apps.get_model("auth", "Group")
    Permission = apps.get_model("auth", "Permission")
    ContentType = apps.get_model("contenttypes", "ContentType")
    GroupObjectPermission = apps.get_model("guardian", "GroupObjectPermission")

    try:
        group = Group.objects.get(name="user")
    except Group.DoesNotExist:
        return

    try:
        content_type = ContentType.objects.get(app_label="servers", model="server")
    except ContentType.DoesNotExist:
        return

    perm_ids = Permission.objects.filter(content_type=content_type).values_list("id", flat=True)
    GroupObjectPermission.objects.filter(
        group_id=group.id,
        permission_id__in=list(perm_ids),
    ).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0005_server_shell_permission"),
        ("guardian", "0001_initial"),
    ]

    operations = [
        migrations.RunPython(remove_user_group_server_perms, migrations.RunPython.noop),
    ]

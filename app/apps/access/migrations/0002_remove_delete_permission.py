from django.db import migrations, models


def remove_delete_accessrequest_perm(apps, schema_editor):
    Permission = apps.get_model("auth", "Permission")
    ContentType = apps.get_model("contenttypes", "ContentType")
    try:
        content_type = ContentType.objects.get(app_label="access", model="accessrequest")
    except ContentType.DoesNotExist:
        return
    Permission.objects.filter(content_type=content_type, codename="delete_accessrequest").delete()


class Migration(migrations.Migration):

    dependencies = [
        ("access", "0001_initial"),
        ("auth", "__latest__"),
        ("contenttypes", "__latest__"),
    ]

    operations = [
        migrations.RunPython(remove_delete_accessrequest_perm, migrations.RunPython.noop),
        migrations.AlterModelOptions(
            name="accessrequest",
            options={
                "verbose_name": "Access request",
                "verbose_name_plural": "Access requests",
                "default_permissions": ("add", "view", "change"),
                "indexes": [
                    models.Index(fields=["status", "requested_at"], name="acc_req_status_req_idx"),
                    models.Index(fields=["server", "status"], name="acc_req_server_status_idx"),
                ],
                "ordering": ["-requested_at"],
            },
        ),
    ]

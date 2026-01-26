from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("access", "0002_remove_delete_permission"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessrequest",
            name="request_shell",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="accessrequest",
            name="request_logs",
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name="accessrequest",
            name="request_users",
            field=models.BooleanField(default=False),
        ),
    ]

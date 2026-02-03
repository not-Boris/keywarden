from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0006_remove_user_group_server_perms"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="ssh_host_public_key",
            field=models.TextField(blank=True),
        ),
        migrations.AddField(
            model_name="server",
            name="ssh_host_fingerprint",
            field=models.CharField(blank=True, max_length=128),
        ),
    ]

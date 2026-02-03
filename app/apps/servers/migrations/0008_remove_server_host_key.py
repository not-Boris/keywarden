from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0007_server_host_key"),
    ]

    operations = [
        migrations.RemoveField(
            model_name="server",
            name="ssh_host_fingerprint",
        ),
        migrations.RemoveField(
            model_name="server",
            name="ssh_host_public_key",
        ),
    ]

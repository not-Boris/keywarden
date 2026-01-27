from django.db import migrations


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0004_server_account"),
    ]

    operations = [
        migrations.AlterModelOptions(
            name="server",
            options={
                "ordering": ["display_name", "hostname", "ipv4", "ipv6"],
                "permissions": [("shell_server", "Can access server shell")],
                "verbose_name": "Server",
                "verbose_name_plural": "Servers",
            },
        ),
    ]

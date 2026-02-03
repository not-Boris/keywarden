from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0008_remove_server_host_key"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="last_heartbeat_at",
            field=models.DateTimeField(blank=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name="server",
            name="last_ping_ms",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
    ]

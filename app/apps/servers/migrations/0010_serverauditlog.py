from django.db import migrations, models
import django.db.models.deletion
from django.utils import timezone


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0009_server_heartbeat_fields"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerAuditLog",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_at", models.DateTimeField(db_index=True)),
                ("received_at", models.DateTimeField(db_index=True, default=timezone.now, editable=False)),
                ("category", models.CharField(db_index=True, max_length=64)),
                ("event_type", models.CharField(db_index=True, max_length=128)),
                ("unit", models.CharField(blank=True, max_length=128)),
                ("priority", models.CharField(blank=True, db_index=True, max_length=16)),
                ("hostname", models.CharField(blank=True, max_length=253)),
                ("username", models.CharField(blank=True, db_index=True, max_length=150)),
                ("principal", models.CharField(blank=True, max_length=255)),
                ("source_ip", models.GenericIPAddressField(blank=True, null=True)),
                ("session_id", models.CharField(blank=True, max_length=128)),
                ("message", models.TextField(blank=True)),
                ("raw", models.TextField(blank=True)),
                ("fields", models.JSONField(blank=True, default=dict)),
                (
                    "server",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="audit_logs", to="servers.server"),
                ),
            ],
            options={
                "verbose_name": "Server audit log",
                "verbose_name_plural": "Server audit logs",
                "ordering": ["-event_at", "-id"],
                "indexes": [
                    models.Index(fields=["server", "event_at"], name="servers_audit_server_event_idx"),
                    models.Index(fields=["server", "category", "event_at"], name="servers_audit_cat_event_idx"),
                    models.Index(fields=["server", "event_type", "event_at"], name="servers_audit_type_event_idx"),
                    models.Index(fields=["server", "username", "event_at"], name="servers_audit_user_event_idx"),
                    models.Index(fields=["server", "source_ip", "event_at"], name="servers_audit_ip_event_idx"),
                ],
            },
        ),
    ]

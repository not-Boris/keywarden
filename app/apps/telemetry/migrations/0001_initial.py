from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ("servers", "0001_initial"),
    ]

    operations = [
        migrations.CreateModel(
            name="TelemetryEvent",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("event_type", models.CharField(db_index=True, max_length=64)),
                ("success", models.BooleanField(db_index=True, default=True)),
                (
                    "source",
                    models.CharField(
                        choices=[
                            ("agent", "Agent"),
                            ("api", "API"),
                            ("ui", "UI"),
                            ("system", "System"),
                        ],
                        db_index=True,
                        default="api",
                        max_length=16,
                    ),
                ),
                ("message", models.TextField(blank=True)),
                ("metadata", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(db_index=True, default=django.utils.timezone.now, editable=False)),
                (
                    "server",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="telemetry_events",
                        to="servers.server",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="telemetry_events",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Telemetry event",
                "verbose_name_plural": "Telemetry events",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["created_at"], name="telemetry_created_at_idx"),
                    models.Index(fields=["event_type"], name="telemetry_event_type_idx"),
                    models.Index(fields=["server", "created_at"], name="telemetry_server_created_idx"),
                    models.Index(fields=["user", "created_at"], name="telemetry_user_created_idx"),
                ],
            },
        ),
    ]

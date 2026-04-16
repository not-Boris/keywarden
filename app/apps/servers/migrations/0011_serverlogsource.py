from django.db import migrations, models
import django.db.models.deletion
from django.utils import timezone


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0010_serverauditlog"),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerLogSource",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("kind", models.CharField(choices=[("service", "Service"), ("file", "File")], db_index=True, max_length=16)),
                ("name", models.CharField(blank=True, max_length=128)),
                ("service_unit", models.CharField(blank=True, max_length=128)),
                ("file_path", models.CharField(blank=True, max_length=512)),
                ("category_override", models.CharField(blank=True, max_length=64)),
                ("event_type_override", models.CharField(blank=True, max_length=128)),
                ("enabled", models.BooleanField(db_index=True, default=True)),
                ("created_at", models.DateTimeField(default=timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "server",
                    models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name="log_sources", to="servers.server"),
                ),
            ],
            options={
                "verbose_name": "Server log source",
                "verbose_name_plural": "Server log sources",
                "ordering": ["server_id", "kind", "name", "id"],
                "indexes": [
                    models.Index(fields=["server", "enabled", "kind"], name="srvsrc_srv_en_kind_idx"),
                    models.Index(fields=["server", "service_unit"], name="srvsrc_srv_svc_idx"),
                    models.Index(fields=["server", "file_path"], name="servers_src_server_file_idx"),
                ],
            },
        ),
    ]

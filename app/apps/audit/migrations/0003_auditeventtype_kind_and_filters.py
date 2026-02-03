from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("audit", "0002_alter_auditlog_event_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="auditeventtype",
            name="kind",
            field=models.CharField(
                choices=[("api", "API"), ("websocket", "WebSocket")],
                db_index=True,
                default="api",
                help_text="Whether this event type applies to API or WebSocket traffic.",
                max_length=16,
            ),
        ),
        migrations.AddField(
            model_name="auditeventtype",
            name="endpoints",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text=(
                    "List of endpoint patterns that should generate this event type. "
                    "Use one pattern per line in the admin form. Supports '*' wildcards "
                    "and optional METHOD prefixes like 'GET /api/v1/servers/*'."
                ),
            ),
        ),
        migrations.AddField(
            model_name="auditeventtype",
            name="ip_whitelist_enabled",
            field=models.BooleanField(
                default=False,
                help_text="If enabled, only IPs in the whitelist will generate this event type.",
            ),
        ),
        migrations.AddField(
            model_name="auditeventtype",
            name="ip_whitelist",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of allowed IP addresses or CIDR ranges. One per line in the admin form.",
            ),
        ),
        migrations.AddField(
            model_name="auditeventtype",
            name="ip_blacklist_enabled",
            field=models.BooleanField(
                default=False,
                help_text="If enabled, IPs in the blacklist will be blocked for this event type.",
            ),
        ),
        migrations.AddField(
            model_name="auditeventtype",
            name="ip_blacklist",
            field=models.JSONField(
                blank=True,
                default=list,
                help_text="List of denied IP addresses or CIDR ranges. One per line in the admin form.",
            ),
        ),
    ]

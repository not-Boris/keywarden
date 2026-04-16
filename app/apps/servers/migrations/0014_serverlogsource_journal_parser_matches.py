from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0013_server_agent_api_token_hash"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverlogsource",
            name="exclude_matches",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="serverlogsource",
            name="include_matches",
            field=models.JSONField(blank=True, default=dict),
        ),
        migrations.AddField(
            model_name="serverlogsource",
            name="parser",
            field=models.CharField(
                choices=[
                    ("none", "None"),
                    ("syslog", "Syslog"),
                    ("nginx_access", "Nginx Access"),
                    ("json", "JSON"),
                ],
                default="none",
                max_length=32,
            ),
        ),
        migrations.AlterField(
            model_name="serverlogsource",
            name="kind",
            field=models.CharField(
                choices=[("journal", "Journal"), ("service", "Service"), ("file", "File")],
                db_index=True,
                max_length=16,
            ),
        ),
    ]

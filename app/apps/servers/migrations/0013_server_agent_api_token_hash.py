from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("servers", "0012_serverauditlog_source_fields"),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="agent_api_token_hash",
            field=models.CharField(blank=True, db_index=True, max_length=64, null=True),
        ),
    ]

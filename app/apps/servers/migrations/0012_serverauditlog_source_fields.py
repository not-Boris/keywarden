from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0011_serverlogsource"),
    ]

    operations = [
        migrations.AddField(
            model_name="serverauditlog",
            name="source_kind",
            field=models.CharField(blank=True, db_index=True, max_length=16),
        ),
        migrations.AddField(
            model_name="serverauditlog",
            name="source_name",
            field=models.CharField(blank=True, db_index=True, max_length=512),
        ),
        migrations.AddIndex(
            model_name="serverauditlog",
            index=models.Index(fields=["server", "source_kind", "event_at"], name="servers_audit_kind_event_idx"),
        ),
        migrations.AddIndex(
            model_name="serverauditlog",
            index=models.Index(fields=["server", "source_name", "event_at"], name="servers_audit_name_event_idx"),
        ),
    ]

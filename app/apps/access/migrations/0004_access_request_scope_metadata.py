from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("access", "0003_access_request_options"),
    ]

    operations = [
        migrations.AddField(
            model_name="accessrequest",
            name="requested_duration_hours",
            field=models.PositiveIntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="accessrequest",
            name="requested_server_username",
            field=models.CharField(blank=True, max_length=128),
        ),
    ]

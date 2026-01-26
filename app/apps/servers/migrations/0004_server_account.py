from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0003_agent_ca"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ServerAccount",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("system_username", models.CharField(max_length=128)),
                ("is_present", models.BooleanField(db_index=True, default=False)),
                ("last_synced_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                (
                    "server",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="accounts",
                        to="servers.server",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="server_accounts",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Server account",
                "verbose_name_plural": "Server accounts",
                "ordering": ["server_id", "user_id"],
            },
        ),
        migrations.AddConstraint(
            model_name="serveraccount",
            constraint=models.UniqueConstraint(fields=("server", "user"), name="unique_server_account"),
        ),
        migrations.AddIndex(
            model_name="serveraccount",
            index=models.Index(fields=["server", "user"], name="servers_account_user_idx"),
        ),
        migrations.AddIndex(
            model_name="serveraccount",
            index=models.Index(fields=["server", "is_present"], name="servers_account_present_idx"),
        ),
    ]

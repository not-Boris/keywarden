from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SSHKey",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(max_length=128)),
                ("public_key", models.TextField()),
                ("key_type", models.CharField(max_length=32)),
                ("fingerprint", models.CharField(db_index=True, max_length=128)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("last_used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ssh_keys",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "SSH key",
                "verbose_name_plural": "SSH keys",
                "ordering": ["-created_at"],
                "indexes": [
                    models.Index(fields=["user", "is_active"], name="keys_user_active_idx"),
                    models.Index(fields=["fingerprint"], name="keys_fingerprint_idx"),
                ],
                "constraints": [
                    models.UniqueConstraint(
                        fields=("user", "fingerprint"),
                        name="unique_user_key_fingerprint",
                    )
                ],
            },
        ),
    ]

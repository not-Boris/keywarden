from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0005_unique_user_email_index"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ErasureRequest",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("reason", models.TextField()),
                (
                    "status",
                    models.CharField(
                        choices=[("pending", "Pending"), ("denied", "Denied"), ("processed", "Processed")],
                        db_index=True,
                        default="pending",
                        max_length=16,
                    ),
                ),
                ("requested_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("decided_at", models.DateTimeField(blank=True, null=True)),
                ("decision_reason", models.TextField(blank=True)),
                ("processed_at", models.DateTimeField(blank=True, null=True)),
                (
                    "decided_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="erasure_decisions",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "processed_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="erasure_processes",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="erasure_requests",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Erasure request",
                "verbose_name_plural": "Erasure requests",
                "ordering": ["-requested_at"],
            },
        ),
        migrations.AddIndex(
            model_name="erasurerequest",
            index=models.Index(fields=["status", "requested_at"], name="accounts_erasure_status_idx"),
        ),
        migrations.AddIndex(
            model_name="erasurerequest",
            index=models.Index(fields=["user", "status"], name="accounts_er_user_status_idx"),
        ),
    ]

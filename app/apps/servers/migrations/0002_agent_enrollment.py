from django.conf import settings
from django.db import migrations, models
import django.utils.timezone
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.AddField(
            model_name="server",
            name="agent_cert_fingerprint",
            field=models.CharField(blank=True, max_length=128, null=True),
        ),
        migrations.AddField(
            model_name="server",
            name="agent_cert_serial",
            field=models.CharField(blank=True, max_length=64, null=True),
        ),
        migrations.AddField(
            model_name="server",
            name="agent_enrolled_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.CreateModel(
            name="EnrollmentToken",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("token", models.CharField(max_length=128, unique=True)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("expires_at", models.DateTimeField(blank=True, null=True)),
                ("used_at", models.DateTimeField(blank=True, null=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="server_enrollment_tokens",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
                (
                    "server",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="enrollment_tokens",
                        to="servers.server",
                    ),
                ),
            ],
            options={
                "verbose_name": "Enrollment token",
                "verbose_name_plural": "Enrollment tokens",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="enrollmenttoken",
            index=models.Index(fields=["created_at"], name="servers_enroll_created_idx"),
        ),
        migrations.AddIndex(
            model_name="enrollmenttoken",
            index=models.Index(fields=["used_at"], name="servers_enroll_used_idx"),
        ),
    ]

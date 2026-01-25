from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("servers", "0002_agent_enrollment"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="AgentCertificateAuthority",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="Keywarden Agent CA", max_length=128)),
                ("cert_pem", models.TextField()),
                ("key_pem", models.TextField()),
                ("fingerprint", models.CharField(blank=True, max_length=128)),
                ("serial", models.CharField(blank=True, max_length=64)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="agent_certificate_authorities",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "Agent certificate authority",
                "verbose_name_plural": "Agent certificate authorities",
                "ordering": ["-created_at"],
            },
        ),
    ]

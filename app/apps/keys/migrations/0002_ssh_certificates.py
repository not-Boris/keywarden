from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ("keys", "0001_initial"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="SSHCertificateAuthority",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("name", models.CharField(default="Keywarden User SSH CA", max_length=128)),
                ("public_key", models.TextField(blank=True)),
                ("private_key", models.TextField(blank=True)),
                ("fingerprint", models.CharField(blank=True, max_length=128)),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                (
                    "created_by",
                    models.ForeignKey(
                        blank=True,
                        null=True,
                        on_delete=django.db.models.deletion.SET_NULL,
                        related_name="ssh_certificate_authorities",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "SSH certificate authority",
                "verbose_name_plural": "SSH certificate authorities",
                "ordering": ["-created_at"],
            },
        ),
        migrations.CreateModel(
            name="SSHCertificate",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("certificate", models.TextField()),
                ("serial", models.BigIntegerField()),
                ("principals", models.JSONField(blank=True, default=list)),
                ("valid_after", models.DateTimeField()),
                ("valid_before", models.DateTimeField()),
                ("created_at", models.DateTimeField(default=django.utils.timezone.now, editable=False)),
                ("revoked_at", models.DateTimeField(blank=True, null=True)),
                ("is_active", models.BooleanField(db_index=True, default=True)),
                (
                    "key",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="certificate",
                        to="keys.sshkey",
                    ),
                ),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="ssh_certificates",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "SSH certificate",
                "verbose_name_plural": "SSH certificates",
                "ordering": ["-created_at"],
            },
        ),
        migrations.AddIndex(
            model_name="sshcertificate",
            index=models.Index(fields=["user", "is_active"], name="keys_cert_user_active_idx"),
        ),
        migrations.AddIndex(
            model_name="sshcertificate",
            index=models.Index(fields=["valid_before"], name="keys_cert_valid_before_idx"),
        ),
    ]

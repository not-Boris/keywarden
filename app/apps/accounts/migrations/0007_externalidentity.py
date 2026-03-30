from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("accounts", "0006_erasure_request"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name="ExternalIdentity",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("provider_type", models.CharField(choices=[("oidc", "OIDC"), ("social", "Social")], db_index=True, max_length=16)),
                ("provider_id", models.CharField(db_index=True, max_length=64)),
                ("issuer", models.CharField(blank=True, max_length=255)),
                ("subject", models.CharField(max_length=255)),
                ("email_at_link", models.EmailField(max_length=254)),
                ("details", models.JSONField(blank=True, default=dict)),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
                ("last_login_at", models.DateTimeField(blank=True, null=True)),
                (
                    "user",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="external_identities",
                        to=settings.AUTH_USER_MODEL,
                    ),
                ),
            ],
            options={
                "verbose_name": "External identity",
                "verbose_name_plural": "External identities",
            },
        ),
        migrations.AddConstraint(
            model_name="externalidentity",
            constraint=models.UniqueConstraint(
                fields=("provider_type", "provider_id", "subject"),
                name="acct_extid_prv_subj_uniq",
            ),
        ),
        migrations.AddIndex(
            model_name="externalidentity",
            index=models.Index(fields=["user", "provider_type"], name="acct_extid_user_prv_idx"),
        ),
    ]

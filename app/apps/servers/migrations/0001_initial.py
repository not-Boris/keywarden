from django.db import migrations, models
import django.core.validators


class Migration(migrations.Migration):
    initial = True

    dependencies = []

    operations = [
        migrations.CreateModel(
            name="Server",
            fields=[
                ("id", models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name="ID")),
                ("display_name", models.CharField(max_length=128)),
                (
                    "hostname",
                    models.CharField(
                        blank=True,
                        max_length=253,
                        null=True,
                        unique=True,
                        validators=[
                            django.core.validators.RegexValidator(
                                message="Enter a valid hostname.",
                                regex="^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\\.?$",
                            )
                        ],
                    ),
                ),
                ("ipv4", models.GenericIPAddressField(blank=True, null=True, protocol="IPv4", unique=True)),
                ("ipv6", models.GenericIPAddressField(blank=True, null=True, protocol="IPv6", unique=True)),
                ("image", models.ImageField(blank=True, null=True, upload_to="servers/")),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                ("updated_at", models.DateTimeField(auto_now=True)),
            ],
            options={
                "verbose_name": "Server",
                "verbose_name_plural": "Servers",
                "ordering": ["display_name", "hostname", "ipv4", "ipv6"],
            },
        ),
    ]



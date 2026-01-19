from django.conf import settings
from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0004_delete_account"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RunSQL(
            sql=(
                "CREATE UNIQUE INDEX IF NOT EXISTS auth_user_email_uniq "
                "ON auth_user (email);"
            ),
            reverse_sql="DROP INDEX IF EXISTS auth_user_email_uniq;",
        ),
    ]

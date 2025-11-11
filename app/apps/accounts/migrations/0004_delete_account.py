from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0003_alter_account_email"),
    ]

    operations = [
        migrations.DeleteModel(
            name="Account",
        ),
    ]



from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("accounts", "0002_rename_accounts_account"),
    ]

    operations = [
        migrations.AlterField(
            model_name="account",
            name="email",
            field=models.EmailField(max_length=254, unique=True),
        ),
    ]



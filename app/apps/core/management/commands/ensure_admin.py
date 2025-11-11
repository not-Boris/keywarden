import os

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand


class Command(BaseCommand):
    help = "Ensure a Django superuser exists using environment variables"

    def handle(self, *args, **options):
        username = (
            os.getenv("DJANGO_SUPERUSER_USERNAME")
            or os.getenv("KEYWARDEN_ADMIN_USERNAME")
        )
        email = (
            os.getenv("DJANGO_SUPERUSER_EMAIL")
            or os.getenv("KEYWARDEN_ADMIN_EMAIL")
        )
        password = (
            os.getenv("DJANGO_SUPERUSER_PASSWORD")
            or os.getenv("KEYWARDEN_ADMIN_PASSWORD")
        )

        if not username or not email or not password:
            self.stdout.write(
                self.style.WARNING(
                    "Superuser env vars not fully set; skipping ensure_admin. "
                    "Set DJANGO_SUPERUSER_USERNAME, DJANGO_SUPERUSER_EMAIL, "
                    "DJANGO_SUPERUSER_PASSWORD (or KEYWARDEN_ADMIN_*)."
                )
            )
            return

        User = get_user_model()

        user, created = User.objects.get_or_create(username=username, defaults={
            "email": email,
            "is_staff": True,
            "is_superuser": True,
        })

        if created:
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Superuser '{username}' created."))
            return

        changed = False

        if user.email != email:
            user.email = email
            changed = True

        # Ensure flags are correct
        if not user.is_staff:
            user.is_staff = True
            changed = True
        if not user.is_superuser:
            user.is_superuser = True
            changed = True

        if changed:
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Superuser '{username}' updated."))
        else:
            self.stdout.write(self.style.SUCCESS(f"Superuser '{username}' already present."))



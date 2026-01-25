from django.apps import AppConfig


class AccessConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.access"
    verbose_name = "Access Requests"

    def ready(self) -> None:
        from . import signals  # noqa: F401
        return super().ready()

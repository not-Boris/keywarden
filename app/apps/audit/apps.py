from django.apps import AppConfig


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.audit"
    label = "audit"
    verbose_name = "Audit"

    def ready(self) -> None:
        # Import signal handlers
        from . import signals  # noqa: F401
        return super().ready()



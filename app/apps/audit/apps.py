from django.apps import AppConfig
from django.db.models.signals import post_delete, post_save


class AuditConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.audit"
    label = "audit"
    verbose_name = "Audit"

    def ready(self) -> None:
        # Import signal handlers
        from . import signals  # noqa: F401
        from .matching import clear_event_type_cache
        from .models import AuditEventType

        post_save.connect(clear_event_type_cache, sender=AuditEventType)
        post_delete.connect(clear_event_type_cache, sender=AuditEventType)
        return super().ready()


from django.apps import AppConfig


class KeysConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.keys"
    verbose_name = "SSH Keys"

    def ready(self) -> None:
        from . import signals  # noqa: F401
        return super().ready()

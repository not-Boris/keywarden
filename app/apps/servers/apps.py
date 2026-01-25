from django.apps import AppConfig


class ServersConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.servers"
    verbose_name = "Servers"

    def ready(self) -> None:
        from . import signals  # noqa: F401
        return super().ready()


from __future__ import annotations

from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    label = "core"
    verbose_name = "Core"

    def ready(self) -> None:
        from .rbac import ensure_role_groups

        def _ensure_roles(**_kwargs) -> None:
            ensure_role_groups()

        post_migrate.connect(_ensure_roles, sender=self)
        return super().ready()

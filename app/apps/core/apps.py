from __future__ import annotations

from django.apps import AppConfig
from django.db.models.signals import post_migrate


class CoreConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "apps.core"
    label = "core"
    verbose_name = "Core"

    def ready(self) -> None:
        from .rbac import assign_role_permissions, ensure_role_groups

        def _ensure_roles(**_kwargs) -> None:
            ensure_role_groups()
            assign_role_permissions()

        post_migrate.connect(_ensure_roles, dispatch_uid="core_rbac")
        return super().ready()

from __future__ import annotations

from django.contrib.auth.models import Group, Permission
from guardian.shortcuts import assign_perm
from ninja.errors import HttpError

ROLE_ADMIN = "administrator"
ROLE_OPERATOR = "operator"
ROLE_AUDITOR = "auditor"
ROLE_USER = "user"

ROLE_ORDER = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR, ROLE_USER)
ROLE_ALL = ROLE_ORDER
ROLE_ALIASES = {"admin": ROLE_ADMIN}
ROLE_INPUTS = tuple(sorted(set(ROLE_ORDER) | set(ROLE_ALIASES.keys())))

def _model_perms(app_label: str, model: str, actions: list[str]) -> list[str]:
    return [f"{app_label}.{action}_{model}" for action in actions]


ROLE_PERMISSIONS = {
    ROLE_ADMIN: [],
    ROLE_OPERATOR: [
        *_model_perms("servers", "server", ["view"]),
        *_model_perms("access", "accessrequest", ["add", "view", "change", "delete"]),
        *_model_perms("keys", "sshkey", ["add", "view", "change", "delete"]),
        *_model_perms("telemetry", "telemetryevent", ["add", "view"]),
        *_model_perms("audit", "auditlog", ["view"]),
        *_model_perms("audit", "auditeventtype", ["view"]),
        *_model_perms("auth", "user", ["add", "view"]),
    ],
    ROLE_AUDITOR: [
        *_model_perms("audit", "auditlog", ["view"]),
        *_model_perms("audit", "auditeventtype", ["view"]),
    ],
    ROLE_USER: [
        *_model_perms("servers", "server", ["view"]),
        *_model_perms("access", "accessrequest", ["add"]),
        *_model_perms("keys", "sshkey", ["add"]),
    ],
}

OBJECT_PERMISSION_MODELS = {
    ("servers", "server"),
    ("access", "accessrequest"),
    ("keys", "sshkey"),
}


def normalize_role(role: str) -> str:
    normalized = (role or "").strip().lower()
    return ROLE_ALIASES.get(normalized, normalized)


def ensure_role_groups() -> None:
    for role in ROLE_ORDER:
        Group.objects.get_or_create(name=role)


def assign_role_permissions() -> None:
    ensure_role_groups()
    for role, perm_codes in ROLE_PERMISSIONS.items():
        group = Group.objects.get(name=role)
        if role == ROLE_ADMIN:
            group.permissions.set(Permission.objects.all())
            continue
        perms = []
        for code in perm_codes:
            if "." not in code:
                continue
            app_label, codename = code.split(".", 1)
            try:
                perms.append(
                    Permission.objects.get(
                        content_type__app_label=app_label,
                        codename=codename,
                    )
                )
            except Permission.DoesNotExist:
                continue
        group.permissions.set(perms)


def assign_default_object_permissions(instance) -> None:
    app_label = instance._meta.app_label
    model_name = instance._meta.model_name
    if (app_label, model_name) not in OBJECT_PERMISSION_MODELS:
        return
    ensure_role_groups()
    groups = {group.name: group for group in Group.objects.filter(name__in=ROLE_ORDER)}
    for role, perm_codes in ROLE_PERMISSIONS.items():
        if role == ROLE_ADMIN:
            continue
        group = groups.get(role)
        if not group:
            continue
        for code in perm_codes:
            if "." not in code:
                continue
            perm_app, codename = code.split(".", 1)
            if perm_app != app_label:
                continue
            if not codename.endswith(f"_{model_name}"):
                continue
            if codename.startswith("add_"):
                continue
            assign_perm(code, group, instance)


def get_user_role(user, default: str = ROLE_USER) -> str | None:
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if getattr(user, "is_superuser", False):
        return ROLE_ADMIN
    group_names = set(user.groups.values_list("name", flat=True))
    for role in ROLE_ORDER:
        if role in group_names:
            return role
    return default


def set_user_role(user, role: str) -> str:
    canonical = normalize_role(role)
    if canonical not in ROLE_ORDER:
        raise ValueError(f"Invalid role: {role}")
    ensure_role_groups()
    role_groups = list(Group.objects.filter(name__in=ROLE_ORDER))
    if role_groups:
        user.groups.remove(*role_groups)
    target_group = Group.objects.get(name=canonical)
    user.groups.add(target_group)
    if canonical == ROLE_ADMIN:
        user.is_staff = True
        user.is_superuser = True
    elif canonical in {ROLE_OPERATOR, ROLE_AUDITOR}:
        user.is_staff = True
        user.is_superuser = False
    else:
        user.is_staff = False
        user.is_superuser = False
    return canonical


def require_authenticated(request) -> None:
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")


def require_perms(request, *perms: str) -> None:
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")
    if not user.has_perms(perms):
        raise HttpError(403, "Forbidden")

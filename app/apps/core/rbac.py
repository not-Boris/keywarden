from __future__ import annotations

from django.contrib.auth.models import Group
from ninja.errors import HttpError

ROLE_ADMIN = "administrator"
ROLE_OPERATOR = "operator"
ROLE_AUDITOR = "auditor"
ROLE_USER = "user"

ROLE_ORDER = (ROLE_ADMIN, ROLE_OPERATOR, ROLE_AUDITOR, ROLE_USER)
ROLE_ALL = ROLE_ORDER
ROLE_ALIASES = {"admin": ROLE_ADMIN}
ROLE_INPUTS = tuple(sorted(set(ROLE_ORDER) | set(ROLE_ALIASES.keys())))


def normalize_role(role: str) -> str:
    normalized = (role or "").strip().lower()
    return ROLE_ALIASES.get(normalized, normalized)


def ensure_role_groups() -> None:
    for role in ROLE_ORDER:
        Group.objects.get_or_create(name=role)


def get_user_role(user, default: str = ROLE_USER) -> str | None:
    if not user or not getattr(user, "is_authenticated", False):
        return None
    if getattr(user, "is_superuser", False):
        return ROLE_ADMIN
    group_names = set(user.groups.values_list("name", flat=True))
    for role in ROLE_ORDER:
        if role in group_names:
            return role
    if getattr(user, "is_staff", False):
        return ROLE_ADMIN
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
    else:
        user.is_staff = False
        user.is_superuser = False
    return canonical


def require_authenticated(request) -> None:
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")


def require_roles(request, *roles: str) -> None:
    user = getattr(request, "user", None)
    if not user or not getattr(user, "is_authenticated", False):
        raise HttpError(403, "Forbidden")
    role = get_user_role(user)
    if role == ROLE_ADMIN:
        return
    allowed = {normalize_role(entry) for entry in roles}
    if role not in allowed:
        raise HttpError(403, "Forbidden")

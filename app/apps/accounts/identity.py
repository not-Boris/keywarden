from __future__ import annotations

import re
from typing import Iterable, Mapping

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from django.utils import timezone

from apps.core.rbac import ROLE_ADMIN, ROLE_USER, get_user_role, set_user_role

from .models import ExternalIdentity

_USERNAME_SANITIZER = re.compile(r"[^a-zA-Z0-9._-]+")


def normalize_email(raw_email: str | None) -> str:
    return (raw_email or "").strip().lower()


def parse_groups(raw_groups) -> set[str]:
    if raw_groups is None:
        return set()
    if isinstance(raw_groups, (list, tuple, set)):
        items = raw_groups
    elif isinstance(raw_groups, str):
        # Support comma-separated and space-separated group claims.
        items = [part for token in raw_groups.split(",") for part in token.split()]
    else:
        items = [str(raw_groups)]

    normalized = set()
    for item in items:
        value = str(item).strip().lower()
        if value:
            normalized.add(value)
    return normalized


def claim_text(claims: Mapping[str, object], key: str, default: str = "") -> str:
    value = claims.get(key, default)
    if value is None:
        return default
    return str(value).strip()


def claim_bool(claims: Mapping[str, object], key: str, default: bool = False) -> bool:
    value = claims.get(key)
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def build_unique_username(preferred: str, email: str) -> str:
    User = get_user_model()
    max_len = User._meta.get_field("username").max_length

    base = (preferred or "").strip().lower()
    if not base:
        base = email.split("@", 1)[0]
    base = _USERNAME_SANITIZER.sub("-", base).strip("-._")
    if not base:
        base = "user"
    base = base[:max_len]

    candidate = base
    counter = 1
    while User.objects.filter(username__iexact=candidate).exists():
        suffix = f"-{counter}"
        trimmed = base[: max_len - len(suffix)]
        candidate = f"{trimmed}{suffix}"
        counter += 1
    return candidate


def upsert_external_identity(
    *,
    user,
    provider_type: str,
    provider_id: str,
    subject: str,
    email: str,
    issuer: str = "",
    details: Mapping[str, object] | None = None,
) -> ExternalIdentity:
    provider_id = (provider_id or "").strip()
    subject = (subject or "").strip()
    if not provider_id or not subject:
        raise IntegrityError("External identity provider and subject are required.")

    normalized_email = normalize_email(email)
    identity_defaults = {
        "user": user,
        "issuer": (issuer or "").strip(),
        "email_at_link": normalized_email,
        "details": dict(details or {}),
        "last_login_at": timezone.now(),
    }

    with transaction.atomic():
        identity, created = ExternalIdentity.objects.select_for_update().get_or_create(
            provider_type=provider_type,
            provider_id=provider_id,
            subject=subject,
            defaults=identity_defaults,
        )

        if not created and identity.user_id != user.id:
            raise IntegrityError("External identity subject is already linked to another user.")

        changed = False
        if identity.user_id != user.id:
            identity.user = user
            changed = True
        if identity.issuer != identity_defaults["issuer"]:
            identity.issuer = identity_defaults["issuer"]
            changed = True
        if identity.email_at_link != normalized_email:
            # Keep the enrolled email immutable to avoid identity confusion.
            raise IntegrityError("External identity email mismatch.")

        identity.details = dict(details or {})
        identity.last_login_at = identity_defaults["last_login_at"]
        if created:
            return identity
        identity.save(update_fields=["details", "last_login_at"] + (["issuer"] if changed else []))
        return identity


def apply_optional_role_mapping(
    *,
    user,
    groups: Iterable[str],
    enabled: bool,
    admin_groups: Iterable[str],
    demote_on_miss: bool,
) -> str | None:
    if not enabled:
        return None

    user_groups = parse_groups(groups)
    admin_groups_normalized = parse_groups(list(admin_groups))
    if not admin_groups_normalized:
        return None

    if user_groups & admin_groups_normalized:
        set_user_role(user, ROLE_ADMIN)
        user.save(update_fields=["is_staff", "is_superuser"])
        return ROLE_ADMIN

    if demote_on_miss and get_user_role(user, default=ROLE_USER) != ROLE_USER:
        set_user_role(user, ROLE_USER)
        user.save(update_fields=["is_staff", "is_superuser"])
        return ROLE_USER

    return None

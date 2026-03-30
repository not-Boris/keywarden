from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.shortcuts import redirect

from allauth.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

from apps.core.rbac import ROLE_USER, get_user_role, set_user_role

from .identity import (
    build_unique_username,
    normalize_email,
    parse_groups,
    upsert_external_identity,
)
from .models import ExternalIdentity


class KeywardenSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        email = self._extract_email(sociallogin)
        provider = sociallogin.account.provider
        subject = str(sociallogin.account.uid or "").strip()
        if not subject:
            self._reject(request, "Login failed: provider did not return a stable user id.")

        if not email:
            self._reject(request, "Login failed: provider did not return an email address.")
        if getattr(settings, "KEYWARDEN_SOCIAL_REQUIRE_VERIFIED_EMAIL", True):
            if not self._email_verified(sociallogin, email):
                self._reject(request, "Login failed: provider email is not verified.")

        if sociallogin.is_existing:
            if normalize_email(sociallogin.user.email) != email:
                raise PermissionDenied("Social login email does not match enrolled account email.")
            self._sync_identity(sociallogin.user, sociallogin)
            return

        existing_link = (
            ExternalIdentity.objects.select_related("user")
            .filter(
                provider_type=ExternalIdentity.ProviderType.SOCIAL,
                provider_id=provider,
                subject=subject,
            )
            .first()
        )
        if existing_link:
            if normalize_email(existing_link.user.email) != email:
                raise PermissionDenied("Linked social account email mismatch.")
            sociallogin.connect(request, existing_link.user)
            self._sync_identity(existing_link.user, sociallogin)
            return

        user = get_user_model().objects.filter(email__iexact=email).first()
        if user:
            sociallogin.connect(request, user)
            self._sync_identity(user, sociallogin)
            return

        if not getattr(settings, "KEYWARDEN_SOCIAL_ALLOW_AUTO_ONBOARDING", False):
            self._reject(
                request,
                "Social auto-onboarding is disabled. Ask an administrator to create/link your account.",
            )

    def populate_user(self, request, sociallogin, data):
        user = super().populate_user(request, sociallogin, data)
        email = self._extract_email(sociallogin)
        preferred_username = (
            data.get("preferred_username")
            or data.get("login")
            or data.get("name")
            or ""
        )
        if email:
            user.email = email
        if not user.username:
            user.username = build_unique_username(str(preferred_username), email)
        return user

    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form=form)
        email = self._extract_email(sociallogin)
        if normalize_email(user.email) != email:
            raise PermissionDenied("Social login email does not match enrolled account email.")
        if get_user_role(user, default=None) is None:
            set_user_role(user, ROLE_USER)
            user.save(update_fields=["is_staff", "is_superuser"])
        self._sync_identity(user, sociallogin)
        return user

    def _sync_identity(self, user, sociallogin) -> None:
        extra_data = dict(sociallogin.account.extra_data or {})
        groups = sorted(parse_groups(extra_data.get("groups")))
        details = {
            "email": self._extract_email(sociallogin),
            "name": str(extra_data.get("name") or "").strip(),
            "groups": groups,
        }

        try:
            upsert_external_identity(
                user=user,
                provider_type=ExternalIdentity.ProviderType.SOCIAL,
                provider_id=sociallogin.account.provider,
                subject=str(sociallogin.account.uid or "").strip(),
                email=self._extract_email(sociallogin),
                details=details,
            )
        except IntegrityError as exc:
            raise PermissionDenied(str(exc)) from exc

    def _extract_email(self, sociallogin) -> str:
        user_email = normalize_email(getattr(sociallogin.user, "email", ""))
        if user_email:
            return user_email
        return normalize_email((sociallogin.account.extra_data or {}).get("email"))

    def _email_verified(self, sociallogin, email: str) -> bool:
        normalized = normalize_email(email)
        for address in getattr(sociallogin, "email_addresses", []):
            if normalize_email(getattr(address, "email", "")) == normalized and bool(getattr(address, "verified", False)):
                return True

        extra_data = sociallogin.account.extra_data or {}
        for claim in ("email_verified", "verified_email", "verified"):
            value = extra_data.get(claim)
            if isinstance(value, bool) and value:
                return True
            if str(value).strip().lower() in {"1", "true", "yes", "on"}:
                return True
        return False

    def _reject(self, request, reason: str) -> None:
        messages.error(request, reason)
        raise ImmediateHttpResponse(redirect("accounts:login"))

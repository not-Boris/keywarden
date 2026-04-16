from __future__ import annotations

from django.conf import settings
from django.contrib import messages
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from django.shortcuts import redirect
from django.urls import reverse

from allauth.exceptions import ImmediateHttpResponse
from allauth.socialaccount.adapter import DefaultSocialAccountAdapter

from .identity import (
    build_unique_username,
    normalize_email,
    parse_groups,
    upsert_external_identity,
)
from .models import ExternalIdentity


class KeywardenSocialAccountAdapter(DefaultSocialAccountAdapter):
    def pre_social_login(self, request, sociallogin):
        provider = str(sociallogin.account.provider or "").strip().lower()
        if provider != "github":
            self._reject(request, "Only GitHub social authentication is enabled.")

        email = self._extract_email(sociallogin)
        subject = str(sociallogin.account.uid or "").strip()
        if not subject:
            self._reject(request, "Login failed: provider did not return a stable user id.")

        if not email:
            self._reject(request, "Login failed: provider did not return an email address.")
        if getattr(settings, "KEYWARDEN_SOCIAL_REQUIRE_VERIFIED_EMAIL", True):
            if not self._email_verified(sociallogin, email):
                self._reject(request, "Login failed: provider email is not verified.")

        if self._is_connect_flow(request, sociallogin):
            self._handle_connect_flow(
                request,
                sociallogin,
                provider=provider,
                subject=subject,
            )
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
        if not existing_link:
            self._reject(
                request,
                "GitHub is not linked for this account. Sign in with your existing method and link GitHub from Profile.",
            )

        if sociallogin.is_existing:
            if getattr(sociallogin.user, "pk", None) != existing_link.user_id:
                raise PermissionDenied("GitHub identity is already linked to another Keywarden account.")
        else:
            sociallogin.connect(request, existing_link.user)

        self._sync_identity(existing_link.user, sociallogin)

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
        raise PermissionDenied("Social auto-onboarding is disabled. Link GitHub from your profile.")

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

    def _handle_connect_flow(self, request, sociallogin, *, provider: str, subject: str) -> None:
        if not request.user.is_authenticated:
            self._reject(
                request,
                "Sign in with Keywarden first, then link GitHub from your profile.",
            )

        user = request.user

        existing_subject_link = (
            ExternalIdentity.objects.select_related("user")
            .filter(
                provider_type=ExternalIdentity.ProviderType.SOCIAL,
                provider_id=provider,
                subject=subject,
            )
            .first()
        )
        if existing_subject_link and existing_subject_link.user_id != user.id:
            raise PermissionDenied("This GitHub account is already linked to another user.")

        existing_provider_link = (
            ExternalIdentity.objects.filter(
                user=user,
                provider_type=ExternalIdentity.ProviderType.SOCIAL,
                provider_id=provider,
            )
            .exclude(subject=subject)
            .first()
        )
        if existing_provider_link:
            self._reject(
                request,
                "A different GitHub account is already linked. Unlink it before linking another account.",
                redirect_to="accounts:profile",
            )

        if sociallogin.is_existing and getattr(sociallogin.user, "pk", None) != user.pk:
            raise PermissionDenied("This GitHub account is already linked to another user.")

        if not sociallogin.is_existing:
            sociallogin.connect(request, user)
        self._sync_identity(user, sociallogin)

    def _is_connect_flow(self, request, sociallogin) -> bool:
        process = str(
            (getattr(sociallogin, "state", {}) or {}).get("process")
            or request.GET.get("process")
            or ""
        ).strip().lower()
        return process == "connect"

    def _extract_email(self, sociallogin) -> str:
        provider_email = normalize_email((sociallogin.account.extra_data or {}).get("email"))
        if provider_email:
            return provider_email
        for address in getattr(sociallogin, "email_addresses", []):
            candidate = normalize_email(getattr(address, "email", ""))
            if candidate:
                return candidate
        return normalize_email(getattr(sociallogin.user, "email", ""))

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

    def _reject(self, request, reason: str, redirect_to: str = "accounts:login") -> None:
        messages.error(request, reason)
        raise ImmediateHttpResponse(redirect(redirect_to))

    def get_connect_redirect_url(self, request, socialaccount):
        return reverse("accounts:profile")

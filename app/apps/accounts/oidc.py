from __future__ import annotations

import logging

from django.conf import settings
from django.core.exceptions import PermissionDenied
from django.db import IntegrityError
from mozilla_django_oidc.auth import OIDCAuthenticationBackend

from apps.core.rbac import ROLE_USER, set_user_role

from .identity import (
    apply_optional_role_mapping,
    build_unique_username,
    claim_bool,
    claim_text,
    normalize_email,
    parse_groups,
    upsert_external_identity,
)
from .models import ExternalIdentity

logger = logging.getLogger(__name__)


class KeywardenOIDCAuthenticationBackend(OIDCAuthenticationBackend):
    def verify_claims(self, claims):
        subject = claim_text(claims, "sub")
        email = self._extract_email(claims)
        if not subject or not email:
            logger.warning(
                "OIDC claims rejected: missing required subject/email claims (sub=%s, email=%s).",
                bool(subject),
                bool(email),
            )
            return False

        if getattr(settings, "KEYWARDEN_OIDC_REQUIRE_VERIFIED_EMAIL", True):
            if not self._email_verified(claims):
                logger.warning("OIDC claims rejected: email verification claim is not true.")
                return False

        expected_issuer = (getattr(settings, "KEYWARDEN_OIDC_ISSUER", "") or "").strip()
        token_issuer = self._extract_issuer(claims)
        if expected_issuer and token_issuer and token_issuer.rstrip("/") != expected_issuer.rstrip("/"):
            logger.warning(
                "OIDC claims rejected: issuer mismatch (expected=%s, got=%s).",
                expected_issuer,
                token_issuer,
            )
            return False

        return True

    def filter_users_by_claims(self, claims):
        subject = claim_text(claims, "sub")
        email = self._extract_email(claims)

        identity = (
            ExternalIdentity.objects.select_related("user")
            .filter(
                provider_type=ExternalIdentity.ProviderType.OIDC,
                provider_id=self._provider_id(),
                subject=subject,
            )
            .first()
        )
        if identity:
            linked_email = normalize_email(identity.user.email)
            if linked_email != email or normalize_email(identity.email_at_link) != email:
                logger.warning(
                    "Rejecting OIDC login due to email mismatch for provider=%s subject=%s",
                    self._provider_id(),
                    subject,
                )
                return self.UserModel.objects.none()
            return self.UserModel.objects.filter(pk=identity.user_id)

        if not email:
            return self.UserModel.objects.none()
        return self.UserModel.objects.filter(email__iexact=email)

    def create_user(self, claims):
        email = self._extract_email(claims)
        username_claim = claim_text(claims, getattr(settings, "KEYWARDEN_OIDC_USERNAME_CLAIM", "preferred_username"))
        user = self.UserModel(
            username=build_unique_username(username_claim, email),
            email=email,
            first_name=claim_text(claims, "given_name"),
            last_name=claim_text(claims, "family_name"),
            is_active=True,
        )
        user.set_unusable_password()
        user.save()
        set_user_role(user, ROLE_USER)
        user.save(update_fields=["is_staff", "is_superuser"])

        self._sync_identity(user, claims)
        self._sync_groups(user, claims)
        return user

    def update_user(self, user, claims):
        email = self._extract_email(claims)
        if normalize_email(user.email) != email:
            raise PermissionDenied("OIDC email does not match enrolled account email.")

        fields_to_update = []
        first_name = claim_text(claims, "given_name")
        last_name = claim_text(claims, "family_name")
        if first_name and first_name != user.first_name:
            user.first_name = first_name
            fields_to_update.append("first_name")
        if last_name and last_name != user.last_name:
            user.last_name = last_name
            fields_to_update.append("last_name")
        if fields_to_update:
            user.save(update_fields=fields_to_update)

        self._sync_identity(user, claims)
        self._sync_groups(user, claims)
        return user

    def _sync_identity(self, user, claims) -> None:
        subject = claim_text(claims, "sub")
        if not subject:
            raise PermissionDenied("OIDC subject claim is required.")

        groups_claim = getattr(settings, "KEYWARDEN_OIDC_GROUPS_CLAIM", "groups")
        groups = sorted(parse_groups(claims.get(groups_claim)))
        details = {
            "email": self._extract_email(claims),
            "name": claim_text(claims, "name"),
            "groups": groups,
        }

        try:
            upsert_external_identity(
                user=user,
                provider_type=ExternalIdentity.ProviderType.OIDC,
                provider_id=self._provider_id(),
                issuer=self._extract_issuer(claims),
                subject=subject,
                email=self._extract_email(claims),
                details=details,
            )
        except IntegrityError as exc:
            raise PermissionDenied(str(exc)) from exc

    def _sync_groups(self, user, claims) -> None:
        groups_claim = getattr(settings, "KEYWARDEN_OIDC_GROUPS_CLAIM", "groups")
        groups = parse_groups(claims.get(groups_claim))
        apply_optional_role_mapping(
            user=user,
            groups=groups,
            enabled=getattr(settings, "KEYWARDEN_OIDC_SYNC_ADMIN_FROM_GROUPS", False),
            admin_groups=getattr(settings, "KEYWARDEN_OIDC_ADMIN_GROUPS", []),
            demote_on_miss=getattr(settings, "KEYWARDEN_OIDC_ADMIN_DEMOTE_ON_MISS", False),
        )

    def _provider_id(self) -> str:
        provider_id = (getattr(settings, "KEYWARDEN_OIDC_PROVIDER_ID", "oidc") or "oidc").strip()
        return provider_id or "oidc"

    def _extract_email(self, claims) -> str:
        email_claim = getattr(settings, "KEYWARDEN_OIDC_EMAIL_CLAIM", "email")
        return normalize_email(claim_text(claims, email_claim))

    def _extract_issuer(self, claims) -> str:
        return claim_text(claims, "iss")

    def _email_verified(self, claims) -> bool:
        claim_name = getattr(settings, "KEYWARDEN_OIDC_EMAIL_VERIFIED_CLAIM", "email_verified")
        return claim_bool(claims, claim_name, default=False)

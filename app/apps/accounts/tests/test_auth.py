from __future__ import annotations

from types import SimpleNamespace

from allauth.exceptions import ImmediateHttpResponse
from django.contrib.auth.models import AnonymousUser
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.middleware import SessionMiddleware
from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.core import signing
from django.test import RequestFactory, TestCase
from django.urls import reverse

from apps.accounts.forms import NativePasswordResetForm
from apps.accounts.identity import (
    apply_optional_role_mapping,
    build_unique_username,
    claim_bool,
    claim_text,
    normalize_email,
    parse_groups,
    upsert_external_identity,
)
from apps.accounts.models import ExternalIdentity, NativeAccountSecurity
from apps.core.rbac import ROLE_ADMIN, ROLE_USER, get_user_role, set_user_role
from apps.accounts.social_auth import KeywardenSocialAccountAdapter


class IdentityHelpersTests(TestCase):
    def test_normalize_email(self):
        self.assertEqual(normalize_email("  USER@Example.Com  "), "user@example.com")

    def test_build_unique_username_appends_suffix(self):
        User = get_user_model()
        User.objects.create_user(username="alice", email="alice@example.com", password="pass12345")
        generated = build_unique_username("alice", "alice2@example.com")
        self.assertNotEqual(generated, "alice")
        self.assertTrue(generated.startswith("alice"))

    def test_parse_groups_supports_multiple_input_shapes(self):
        self.assertEqual(parse_groups(None), set())
        self.assertEqual(parse_groups("Admins, Dev Ops"), {"admins", "dev", "ops"})
        self.assertEqual(parse_groups(["Team-A", " team-b "]), {"team-a", "team-b"})
        self.assertEqual(parse_groups(123), {"123"})

    def test_claim_helpers(self):
        claims = {"name": " Alice ", "enabled": "YES", "flag": False}
        self.assertEqual(claim_text(claims, "name"), "Alice")
        self.assertEqual(claim_text(claims, "missing", "fallback"), "fallback")
        self.assertTrue(claim_bool(claims, "enabled"))
        self.assertFalse(claim_bool(claims, "flag", default=True))
        self.assertTrue(claim_bool(claims, "missing", default=True))


class ImmutableEmailTests(TestCase):
    def test_email_change_is_blocked(self):
        User = get_user_model()
        user = User.objects.create_user(username="bob", email="bob@example.com", password="pass12345")
        user.email = "newbob@example.com"
        with self.assertRaises(ValidationError):
            user.save()


class ExternalIdentityTests(TestCase):
    def test_identity_str(self):
        User = get_user_model()
        user = User.objects.create_user(username="charlie", email="charlie@example.com", password="pass12345")
        identity = ExternalIdentity.objects.create(
            user=user,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="corporate-sso",
            issuer="https://id.example.com/realms/main",
            subject="sub-123",
            email_at_link="charlie@example.com",
        )
        self.assertIn("corporate-sso", str(identity))

    def test_upsert_external_identity_create_and_update(self):
        User = get_user_model()
        user = User.objects.create_user(username="oidc1", email="oidc1@example.com", password="pass12345")
        identity = upsert_external_identity(
            user=user,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="oidc",
            subject="sub-1",
            email="oidc1@example.com",
            issuer="https://issuer.example.com",
            details={"groups": ["admins"]},
        )
        self.assertEqual(identity.user_id, user.id)
        self.assertEqual(identity.issuer, "https://issuer.example.com")
        self.assertEqual(identity.email_at_link, "oidc1@example.com")

        refreshed = upsert_external_identity(
            user=user,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="oidc",
            subject="sub-1",
            email="oidc1@example.com",
            issuer="https://issuer-v2.example.com",
            details={"groups": ["users"]},
        )
        self.assertEqual(refreshed.id, identity.id)
        self.assertEqual(refreshed.issuer, "https://issuer-v2.example.com")
        self.assertEqual(refreshed.details, {"groups": ["users"]})

    def test_upsert_external_identity_rejects_conflicts(self):
        User = get_user_model()
        user1 = User.objects.create_user(username="oidc2", email="oidc2@example.com", password="pass12345")
        user2 = User.objects.create_user(username="oidc3", email="oidc3@example.com", password="pass12345")
        upsert_external_identity(
            user=user1,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="oidc",
            subject="sub-shared",
            email="oidc2@example.com",
        )
        with self.assertRaises(Exception):
            upsert_external_identity(
                user=user2,
                provider_type=ExternalIdentity.ProviderType.OIDC,
                provider_id="oidc",
                subject="sub-shared",
                email="oidc3@example.com",
            )
        with self.assertRaises(Exception):
            upsert_external_identity(
                user=user1,
                provider_type=ExternalIdentity.ProviderType.OIDC,
                provider_id="oidc",
                subject="sub-shared",
                email="different@example.com",
            )


class RoleMappingTests(TestCase):
    def test_apply_optional_role_mapping_promotes_and_demotes(self):
        User = get_user_model()
        user = User.objects.create_user(username="role-map", email="role-map@example.com", password="pass12345")

        promoted = apply_optional_role_mapping(
            user=user,
            groups={"platform-admins"},
            enabled=True,
            admin_groups={"platform-admins"},
            demote_on_miss=False,
        )
        user.refresh_from_db()
        self.assertEqual(promoted, ROLE_ADMIN)
        self.assertEqual(get_user_role(user), ROLE_ADMIN)

        demoted = apply_optional_role_mapping(
            user=user,
            groups={"non-admin"},
            enabled=True,
            admin_groups={"platform-admins"},
            demote_on_miss=True,
        )
        user.refresh_from_db()
        self.assertEqual(demoted, ROLE_USER)
        self.assertEqual(get_user_role(user), ROLE_USER)

    def test_apply_optional_role_mapping_noop_paths(self):
        User = get_user_model()
        user = User.objects.create_user(username="role-map2", email="role-map2@example.com", password="pass12345")
        self.assertIsNone(
            apply_optional_role_mapping(
                user=user,
                groups={"anything"},
                enabled=False,
                admin_groups={"platform-admins"},
                demote_on_miss=True,
            )
        )
        self.assertIsNone(
            apply_optional_role_mapping(
                user=user,
                groups={"platform-admins"},
                enabled=True,
                admin_groups=set(),
                demote_on_miss=True,
            )
        )

    def test_set_user_role_invalid_raises(self):
        User = get_user_model()
        user = User.objects.create_user(username="role-map3", email="role-map3@example.com", password="pass12345")
        with self.assertRaises(ValueError):
            set_user_role(user, "invalid-role")


class _DummySocialLogin:
    def __init__(
        self,
        *,
        email: str,
        provider: str = "github",
        uid: str = "subject-1",
        state: dict | None = None,
        is_existing: bool = False,
        existing_user=None,
        email_verified: bool = True,
    ):
        self.account = SimpleNamespace(
            provider=provider,
            uid=uid,
            extra_data={"email": email, "name": "Test User"},
        )
        self.user = existing_user or SimpleNamespace(email=email, pk=None)
        self.state = state or {}
        self.is_existing = is_existing
        self.email_addresses = [SimpleNamespace(email=email, verified=email_verified)]
        self.connected_user = None

    def connect(self, request, user) -> None:
        self.connected_user = user
        self.user = user
        self.is_existing = True


class SocialAdapterTests(TestCase):
    def setUp(self):
        super().setUp()
        self.factory = RequestFactory()
        self.adapter = KeywardenSocialAccountAdapter()

    def _request(self, *, user=None, path: str = "/accounts/sso/github/login/callback/"):
        request = self.factory.get(path)
        session_middleware = SessionMiddleware(lambda r: None)
        session_middleware.process_request(request)
        request.session.save()
        request._messages = FallbackStorage(request)
        request.user = user or AnonymousUser()
        return request

    def test_login_requires_prelinked_github_identity(self):
        User = get_user_model()
        User.objects.create_user(username="social1", email="social1@example.com", password="pass12345")
        request = self._request()
        sociallogin = _DummySocialLogin(
            email="social1@example.com",
            state={"process": "login"},
        )

        with self.assertRaises(ImmediateHttpResponse):
            self.adapter.pre_social_login(request, sociallogin)

        self.assertFalse(
            ExternalIdentity.objects.filter(
                provider_type=ExternalIdentity.ProviderType.SOCIAL,
                provider_id="github",
            ).exists()
        )

    def test_connect_flow_links_github_to_current_user(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="social2",
            email="social2@example.com",
            password="pass12345",
        )
        request = self._request(user=user)
        sociallogin = _DummySocialLogin(
            email="gh-social2@example.net",
            uid="github-sub-2",
            state={"process": "connect"},
        )

        self.adapter.pre_social_login(request, sociallogin)

        identity = ExternalIdentity.objects.get(
            provider_type=ExternalIdentity.ProviderType.SOCIAL,
            provider_id="github",
            subject="github-sub-2",
        )
        self.assertEqual(identity.user_id, user.id)
        self.assertEqual(identity.email_at_link, "gh-social2@example.net")
        self.assertEqual(sociallogin.connected_user, user)

    def test_login_succeeds_when_github_identity_is_linked(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="social3",
            email="social3@example.com",
            password="pass12345",
        )
        ExternalIdentity.objects.create(
            user=user,
            provider_type=ExternalIdentity.ProviderType.SOCIAL,
            provider_id="github",
            subject="github-sub-3",
            email_at_link="gh-social3@example.net",
        )
        request = self._request()
        sociallogin = _DummySocialLogin(
            email="gh-social3@example.net",
            uid="github-sub-3",
            state={"process": "login"},
        )

        self.adapter.pre_social_login(request, sociallogin)

        self.assertEqual(sociallogin.connected_user, user)
        identity = ExternalIdentity.objects.get(
            provider_type=ExternalIdentity.ProviderType.SOCIAL,
            provider_id="github",
            subject="github-sub-3",
        )
        self.assertIsNotNone(identity.last_login_at)

    def test_connect_flow_allows_local_and_github_email_mismatch(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="social4",
            email="social4@example.com",
            password="pass12345",
        )
        request = self._request(user=user)
        sociallogin = _DummySocialLogin(
            email="different@example.com",
            uid="github-sub-4",
            state={"process": "connect"},
        )

        self.adapter.pre_social_login(request, sociallogin)
        identity = ExternalIdentity.objects.get(
            provider_type=ExternalIdentity.ProviderType.SOCIAL,
            provider_id="github",
            subject="github-sub-4",
        )
        self.assertEqual(identity.user_id, user.id)
        self.assertEqual(identity.email_at_link, "different@example.com")


class NativePasswordResetFormTests(TestCase):
    def test_native_password_reset_excludes_sso_accounts(self):
        User = get_user_model()
        native_user = User.objects.create_user(
            username="native-user",
            email="native@example.com",
            password="pass12345",
        )
        sso_user = User.objects.create_user(
            username="sso-user",
            email="sso@example.com",
            password="pass12345",
        )
        ExternalIdentity.objects.create(
            user=sso_user,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="oidc",
            subject="oidc-subject",
            email_at_link="sso@example.com",
        )

        native_form = NativePasswordResetForm(data={"email": "native@example.com"})
        self.assertTrue(native_form.is_valid())
        native_users = list(native_form.get_users("native@example.com"))
        self.assertEqual([user.pk for user in native_users], [native_user.pk])

        sso_form = NativePasswordResetForm(data={"email": "sso@example.com"})
        self.assertTrue(sso_form.is_valid())
        sso_users = list(sso_form.get_users("sso@example.com"))
        self.assertEqual(sso_users, [])


class NativeEmailVerificationTests(TestCase):
    def test_email_verification_marks_native_account_verified(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="verify-native",
            email="verify-native@example.com",
            password="pass12345",
        )
        token = signing.dumps(
            {"uid": user.pk, "email": "verify-native@example.com"},
            salt="accounts.native-email-verification",
        )

        response = self.client.get(reverse("accounts:email_verify", kwargs={"token": token}))
        self.assertEqual(response.status_code, 302)

        security = NativeAccountSecurity.objects.get(user=user)
        self.assertTrue(security.email_verified)
        self.assertIsNotNone(security.email_verified_at)

    def test_email_verification_does_not_verify_sso_account(self):
        User = get_user_model()
        user = User.objects.create_user(
            username="verify-sso",
            email="verify-sso@example.com",
            password="pass12345",
        )
        ExternalIdentity.objects.create(
            user=user,
            provider_type=ExternalIdentity.ProviderType.OIDC,
            provider_id="oidc",
            subject="sso-subject-verify",
            email_at_link="verify-sso@example.com",
        )
        token = signing.dumps(
            {"uid": user.pk, "email": "verify-sso@example.com"},
            salt="accounts.native-email-verification",
        )

        response = self.client.get(reverse("accounts:email_verify", kwargs={"token": token}))
        self.assertEqual(response.status_code, 302)
        self.assertFalse(NativeAccountSecurity.objects.filter(user=user).exists())

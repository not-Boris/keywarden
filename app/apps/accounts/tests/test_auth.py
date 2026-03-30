from __future__ import annotations

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.test import TestCase

from apps.accounts.identity import build_unique_username, normalize_email
from apps.accounts.models import ExternalIdentity


class IdentityHelpersTests(TestCase):
    def test_normalize_email(self):
        self.assertEqual(normalize_email("  USER@Example.Com  "), "user@example.com")

    def test_build_unique_username_appends_suffix(self):
        User = get_user_model()
        User.objects.create_user(username="alice", email="alice@example.com", password="pass12345")
        generated = build_unique_username("alice", "alice2@example.com")
        self.assertNotEqual(generated, "alice")
        self.assertTrue(generated.startswith("alice"))


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

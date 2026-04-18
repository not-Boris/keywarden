from __future__ import annotations

import os
import tempfile

from django.test import TestCase, override_settings

from apps.core.secret_files import parse_secret_ref
from apps.keys.models import SSHCertificateAuthority
from apps.servers.models import AgentCertificateAuthority


class CASecretFileRecoveryTests(TestCase):
    def test_user_ca_recovers_when_private_key_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = os.path.join(tmpdir, "missing-user-ca-key.pem")
            with override_settings(KEYWARDEN_CA_KEY_DIR=tmpdir):
                ca = SSHCertificateAuthority.objects.create(
                    name="User CA Recovery",
                    public_key="ssh-ed25519 AAAAinvalid",
                    private_key=f"file://{missing_path}",
                    is_active=True,
                )

                ca.ensure_material()
                ca.save()

                self.assertTrue(ca.public_key.startswith("ssh-ed25519 "))
                self.assertTrue(ca.fingerprint.startswith("SHA256:"))
                key_path = parse_secret_ref(ca.private_key)
                self.assertTrue(key_path)
                self.assertTrue(os.path.exists(key_path))
                self.assertIn("BEGIN OPENSSH PRIVATE KEY", ca.get_private_key())

    def test_agent_ca_recovers_when_private_key_file_is_missing(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            missing_path = os.path.join(tmpdir, "missing-agent-ca-key.pem")
            with override_settings(KEYWARDEN_CA_KEY_DIR=tmpdir):
                ca = AgentCertificateAuthority.objects.create(
                    name="Agent CA Recovery",
                    cert_pem="",
                    key_pem=f"file://{missing_path}",
                    is_active=True,
                )

                ca.ensure_material()
                ca.save()

                self.assertIn("BEGIN CERTIFICATE", ca.cert_pem)
                self.assertTrue(ca.fingerprint)
                self.assertTrue(ca.serial)
                key_path = parse_secret_ref(ca.key_pem)
                self.assertTrue(key_path)
                self.assertTrue(os.path.exists(key_path))
                self.assertIn("BEGIN RSA PRIVATE KEY", ca.get_key_pem())

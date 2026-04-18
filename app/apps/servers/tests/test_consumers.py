from __future__ import annotations

import subprocess
import tempfile
from datetime import datetime, timedelta, timezone as dt_timezone
from types import SimpleNamespace
from urllib.parse import quote
from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, Mock, patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from django.conf import settings
from django.test import SimpleTestCase, TestCase, override_settings

from apps.servers.consumers import (
    ShellConsumer,
    _build_ssh_command,
    _format_ssh_host,
    _generate_session_keypair,
    _is_truthy,
    _summarize_probe_output,
    _truncate_lines,
)
from apps.keys import certificates as key_certificates
from apps.keys.utils import render_system_username, sanitize_username
from apps.servers.models import AgentCertificateAuthority, Server
from keywarden.api import security as api_security


class ShellSSHCommandTests(SimpleTestCase):
    def test_build_command_uses_default_remote_shell(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        expected = str(getattr(settings, "KEYWARDEN_SHELL_REMOTE_COMMAND", "/bin/bash")).strip()
        self.assertEqual(command[-1], expected)

    @override_settings(KEYWARDEN_SHELL_REMOTE_COMMAND="/bin/bash -li")
    def test_build_command_appends_configured_remote_shell(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertEqual(command[-2:], ["/bin/bash", "-li"])
        self.assertIn("alice@server.example.test", command)

    @override_settings(KEYWARDEN_SHELL_REMOTE_COMMAND="")
    def test_build_command_can_disable_explicit_remote_shell(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertEqual(command[-1], "alice@server.example.test")

    def test_build_command_can_disable_tty_and_set_timeout(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
            remote_command="true",
            force_tty=False,
            connect_timeout=8,
        )
        self.assertNotIn("-tt", command)
        self.assertIn("ConnectTimeout=8", command)
        self.assertEqual(command[-1], "true")

    def test_build_command_enforces_host_key_verification(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertIn("StrictHostKeyChecking=accept-new", command)
        self.assertIn("UpdateHostKeys=yes", command)
        self.assertNotIn("StrictHostKeyChecking=no", command)
        self.assertNotIn("UserKnownHostsFile=/dev/null", command)
        self.assertNotIn("GlobalKnownHostsFile=/dev/null", command)

    @override_settings(KEYWARDEN_SHELL_STRICT_HOST_KEY_CHECKING="yes")
    def test_build_command_allows_strict_host_key_policy_override(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertIn("StrictHostKeyChecking=yes", command)

    @override_settings(KEYWARDEN_SHELL_REMOTE_COMMAND='"/bin/bash -li')
    def test_build_command_tolerates_invalid_shell_quoting(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertEqual(command[-1], '"/bin/bash -li')


class ShellHelpersTests(SimpleTestCase):
    def test_format_ssh_host_wraps_ipv6(self):
        self.assertEqual(_format_ssh_host("2001:db8::1"), "[2001:db8::1]")
        self.assertEqual(_format_ssh_host("[2001:db8::1]"), "[2001:db8::1]")
        self.assertEqual(_format_ssh_host("server.example.test"), "server.example.test")

    def test_is_truthy_supports_common_values(self):
        self.assertTrue(_is_truthy(True))
        self.assertTrue(_is_truthy("YES"))
        self.assertTrue(_is_truthy("1"))
        self.assertFalse(_is_truthy(False))
        self.assertFalse(_is_truthy(None))
        self.assertFalse(_is_truthy("off"))

    def test_truncate_lines_limits_output(self):
        text = "\n".join([f"line-{idx}" for idx in range(20)])
        clipped = _truncate_lines(text, max_lines=6, max_chars=2000)
        self.assertIn("... (middle omitted) ...", clipped)
        self.assertIn("line-0", clipped)
        self.assertIn("line-19", clipped)

    def test_summarize_probe_output_extracts_highlights(self):
        raw = (
            "debug: Authenticating to host\n"
            "Permission denied (publickey).\n"
            "certificate invalid: bad signature\n"
            "no such user\n"
            "tail marker\n"
        )
        summary = _summarize_probe_output(raw)
        self.assertIn("Detected cause:", summary)
        self.assertIn("SSH authentication was denied", summary)
        self.assertIn("SSH certificate was rejected", summary)
        self.assertIn("Remote user account does not exist", summary)
        self.assertIn("Probe tail:", summary)

    def test_generate_session_keypair_creates_cert_material(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ca = SimpleNamespace(
                private_key="ca-private",
                public_key="ca-public",
                get_private_key=lambda: "ca-private",
            )
            user = SimpleNamespace(id=7)

            def fake_run(cmd, check, capture_output):
                key_path = cmd[cmd.index("-f") + 1]
                with open(key_path, "w", encoding="utf-8") as handle:
                    handle.write("PRIVATE\n")
                with open(key_path + ".pub", "w", encoding="utf-8") as handle:
                    handle.write("ssh-ed25519 AAAATEST comment\n")
                return SimpleNamespace(returncode=0)

            with (
                patch("apps.servers.consumers.get_active_ca", return_value=ca),
                patch("apps.servers.consumers._sign_public_key", return_value="ssh-ed25519-cert-v01 AAAACERT"),
                patch("apps.servers.consumers.subprocess.run", side_effect=fake_run),
                patch("apps.servers.consumers.secrets.randbits", return_value=42),
            ):
                key_path, cert_path = _generate_session_keypair(tmpdir, user, "alice")

            with open(cert_path, "r", encoding="utf-8") as handle:
                cert_body = handle.read()
            self.assertTrue(key_path.endswith("session_key"))
            self.assertTrue(cert_path.endswith("session_key-cert.pub"))
            self.assertIn("AAAACERT", cert_body)

    def test_generate_session_keypair_raises_when_ssh_keygen_missing(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ca = SimpleNamespace(
                private_key="ca-private",
                public_key="ca-public",
                get_private_key=lambda: "ca-private",
            )
            user = SimpleNamespace(id=8)
            with (
                patch("apps.servers.consumers.get_active_ca", return_value=ca),
                patch("apps.servers.consumers.subprocess.run", side_effect=FileNotFoundError("missing")),
            ):
                with self.assertRaises(RuntimeError):
                    _generate_session_keypair(tmpdir, user, "alice")

    def test_generate_session_keypair_raises_on_ssh_keygen_error(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            ca = SimpleNamespace(
                private_key="ca-private",
                public_key="ca-public",
                get_private_key=lambda: "ca-private",
            )
            user = SimpleNamespace(id=9)
            called = subprocess.CalledProcessError(1, ["ssh-keygen"], stderr=b"boom")
            with (
                patch("apps.servers.consumers.get_active_ca", return_value=ca),
                patch("apps.servers.consumers.subprocess.run", side_effect=called),
            ):
                with self.assertRaises(RuntimeError):
                    _generate_session_keypair(tmpdir, user, "alice")


class ShellConsumerAsyncTests(IsolatedAsyncioTestCase):
    async def test_connect_rejects_unauthenticated_user(self):
        consumer = ShellConsumer()
        consumer.scope = {"url_route": {"kwargs": {"server_id": "1"}}}
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_awaited_once_with(code=4401)

    async def test_connect_rejects_missing_server_id(self):
        consumer = ShellConsumer()
        consumer.scope = {"user": SimpleNamespace(is_authenticated=True), "url_route": {"kwargs": {}}}
        consumer.close = AsyncMock()
        await consumer.connect()
        consumer.close.assert_awaited_once_with(code=4400)

    async def test_connect_accepts_and_starts_session(self):
        user = SimpleNamespace(is_authenticated=True, id=5, username="alice")
        server = SimpleNamespace(id=12, hostname="server.example.test", ipv4=None, ipv6=None)
        consumer = ShellConsumer()
        consumer.scope = {"user": user, "url_route": {"kwargs": {"server_id": "12"}}, "path": "/ws/servers/12/shell/"}
        consumer.accept = AsyncMock()
        consumer.send = AsyncMock()
        consumer.close = AsyncMock()
        consumer._get_server = AsyncMock(return_value=server)
        consumer._can_shell = AsyncMock(return_value=True)
        consumer._get_system_username = AsyncMock(return_value="alice_5")
        consumer._audit_websocket_event = AsyncMock()
        consumer._start_ssh = AsyncMock()

        await consumer.connect()

        consumer.accept.assert_awaited_once()
        consumer._start_ssh.assert_awaited_once_with(user)
        consumer.send.assert_any_await(text_data="Connecting...\r\n")
        self.assertEqual(consumer.server_id, 12)
        self.assertEqual(consumer.system_username, "alice_5")
        self.assertEqual(consumer.shell_target, "server.example.test")

    async def test_connect_handles_start_ssh_failure(self):
        user = SimpleNamespace(is_authenticated=True, id=5, username="alice")
        server = SimpleNamespace(id=12, hostname="server.example.test", ipv4=None, ipv6=None)
        consumer = ShellConsumer()
        consumer.scope = {"user": user, "url_route": {"kwargs": {"server_id": "12"}}, "path": "/ws/servers/12/shell/"}
        consumer.accept = AsyncMock()
        consumer.send = AsyncMock()
        consumer.close = AsyncMock()
        consumer._get_server = AsyncMock(return_value=server)
        consumer._can_shell = AsyncMock(return_value=True)
        consumer._get_system_username = AsyncMock(return_value="alice_5")
        consumer._audit_websocket_event = AsyncMock()
        consumer._start_ssh = AsyncMock(side_effect=RuntimeError("boom"))

        await consumer.connect()

        consumer.send.assert_any_await(text_data="Connection failed.\r\n")
        consumer.close.assert_awaited()

    async def test_receive_forwards_payload_to_ssh_stdin(self):
        stdin = SimpleNamespace(write=Mock(), drain=AsyncMock())
        consumer = ShellConsumer()
        consumer.proc = SimpleNamespace(stdin=stdin)
        await consumer.receive(text_data="echo hi")
        stdin.write.assert_called_once()
        stdin.drain.assert_awaited_once()

    async def test_disconnect_terminates_process_and_cleans_tempdir(self):
        user = SimpleNamespace(is_authenticated=True)
        reader_task = SimpleNamespace(cancel=Mock())
        proc = SimpleNamespace(returncode=None, terminate=Mock(), wait=AsyncMock(return_value=0), kill=Mock())
        consumer = ShellConsumer()
        consumer.scope = {"user": user}
        consumer.server_id = 77
        consumer.reader_task = reader_task
        consumer.proc = proc
        consumer.ssh_started = True
        consumer.tempdir_path = "/tmp/keywarden-shell-test"
        consumer._audit_websocket_event = AsyncMock()

        with patch("apps.servers.consumers.shutil.rmtree") as rmtree:
            await consumer.disconnect(1000)

        consumer._audit_websocket_event.assert_awaited_once()
        reader_task.cancel.assert_called_once()
        proc.terminate.assert_called_once()
        rmtree.assert_called_once_with("/tmp/keywarden-shell-test", ignore_errors=True)

    async def test_stream_output_relays_bytes_and_closes(self):
        stdout = SimpleNamespace(read=AsyncMock(side_effect=[b"hello", b""]))
        proc = SimpleNamespace(stdout=stdout, wait=AsyncMock(return_value=0))
        consumer = ShellConsumer()
        consumer.proc = proc
        consumer.send = AsyncMock()
        consumer.close = AsyncMock()

        await consumer._stream_output()

        consumer.send.assert_any_await(bytes_data=b"hello")
        consumer.close.assert_awaited_once()


class SecurityAndCertificateHelperTests(TestCase):
    def test_normalize_agent_token_and_hash(self):
        self.assertEqual(api_security._normalize_agent_token("  Bearer abc123 "), "abc123")
        self.assertEqual(api_security._normalize_agent_token("token-value"), "token-value")
        self.assertEqual(api_security.hash_agent_token(""), "")
        self.assertEqual(
            api_security.hash_agent_token("Bearer test-token"),
            api_security.hash_agent_token("test-token"),
        )

    def _build_ca_and_client_cert(self):
        ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Keywarden Test Agent CA")])
        now = datetime.now(dt_timezone.utc)
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(ca_key, hashes.SHA256())
        )
        ca_cert_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        ca_key_pem = ca_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("utf-8")

        agent_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        client_subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent.example.test")])
        cert = (
            x509.CertificateBuilder()
            .subject_name(client_subject)
            .issuer_name(ca_cert.subject)
            .public_key(agent_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=30))
            .sign(ca_key, hashes.SHA256())
        )
        cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return ca_cert_pem, ca_key_pem, cert_pem, cert

    def test_agent_mtls_auth_accepts_enrolled_server_certificate(self):
        ca_cert_pem, ca_key_pem, cert_pem, cert = self._build_ca_and_client_cert()
        AgentCertificateAuthority.objects.create(
            name="Test Agent CA",
            cert_pem=ca_cert_pem,
            key_pem=ca_key_pem,
            is_active=True,
        )
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        serial = format(cert.serial_number, "x")
        server = Server.objects.create(
            display_name="mtls-1",
            hostname="mtls-1.example.test",
            agent_cert_fingerprint=fingerprint,
            agent_cert_serial=serial,
        )
        request = SimpleNamespace(
            META={
                "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY": "SUCCESS",
                "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe=""),
                "HTTP_X_KEYWARDEN_TLS_CLIENT_FINGERPRINT": fingerprint,
            }
        )
        auth = api_security.AgentMTLSAuth()

        principal = auth.authenticate(request)

        self.assertIsNotNone(principal)
        self.assertEqual(principal.mode, "mtls")
        self.assertEqual(principal.server_id, server.id)

    def test_agent_mtls_auth_accepts_failed_verify_when_cert_is_valid(self):
        ca_cert_pem, ca_key_pem, cert_pem, cert = self._build_ca_and_client_cert()
        AgentCertificateAuthority.objects.create(
            name="Test Agent CA",
            cert_pem=ca_cert_pem,
            key_pem=ca_key_pem,
            is_active=True,
        )
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
        Server.objects.create(
            display_name="mtls-1b",
            hostname="mtls-1b.example.test",
            agent_cert_fingerprint=fingerprint,
            agent_cert_serial=format(cert.serial_number, "x"),
        )
        request = SimpleNamespace(
            META={
                "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY": "FAILED:unable to verify the first certificate",
                "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe=""),
                # nginx $ssl_client_fingerprint is SHA-1 by default.
                "HTTP_X_KEYWARDEN_TLS_CLIENT_FINGERPRINT": cert.fingerprint(hashes.SHA1()).hex(),
            }
        )
        auth = api_security.AgentMTLSAuth()

        principal = auth.authenticate(request)

        self.assertIsNotNone(principal)
        self.assertEqual(principal.mode, "mtls")

    def test_agent_mtls_auth_rejects_missing_or_mismatched_metadata(self):
        ca_cert_pem, ca_key_pem, cert_pem, cert = self._build_ca_and_client_cert()
        AgentCertificateAuthority.objects.create(
            name="Test Agent CA",
            cert_pem=ca_cert_pem,
            key_pem=ca_key_pem,
            is_active=True,
        )
        Server.objects.create(
            display_name="mtls-2",
            hostname="mtls-2.example.test",
            agent_cert_fingerprint=cert.fingerprint(hashes.SHA256()).hex(),
            agent_cert_serial=format(cert.serial_number, "x"),
        )
        auth = api_security.AgentMTLSAuth()

        missing_verify = SimpleNamespace(
            META={"HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe="")}
        )
        self.assertIsNone(auth.authenticate(missing_verify))

        none_verify = SimpleNamespace(
            META={
                "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY": "NONE",
                "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe=""),
            }
        )
        self.assertIsNone(auth.authenticate(none_verify))

        bad_fingerprint = SimpleNamespace(
            META={
                "HTTP_X_KEYWARDEN_TLS_CLIENT_VERIFY": "SUCCESS",
                "HTTP_X_KEYWARDEN_TLS_CLIENT_CERT": quote(cert_pem, safe=""),
                "HTTP_X_KEYWARDEN_TLS_CLIENT_FINGERPRINT": "00" * 32,
            }
        )
        self.assertIsNone(auth.authenticate(bad_fingerprint))

    def test_agent_runtime_auth_falls_back_to_server_token_without_mtls_headers(self):
        server_token = "server-token-123"
        server = Server.objects.create(
            display_name="token-fallback-1",
            hostname="token-fallback-1.example.test",
            agent_api_token_hash=api_security.hash_agent_token(server_token),
        )
        request = SimpleNamespace(
            META={"HTTP_AUTHORIZATION": f"Bearer {server_token}"},
            path="/api/v1/agent/servers/1/log-config",
        )
        auth = api_security.AgentRuntimeAuth()

        principal = auth.authenticate(request)

        self.assertIsNotNone(principal)
        self.assertEqual(principal.mode, "server-token")
        self.assertEqual(principal.server_id, server.id)

    @override_settings(KEYWARDEN_AGENT_API_TOKEN="global-token-123")
    def test_agent_runtime_auth_accepts_global_token_without_mtls_headers(self):
        request = SimpleNamespace(
            META={"HTTP_AUTHORIZATION": "Bearer global-token-123"},
            path="/api/v1/agent/servers/1/log-config",
        )
        auth = api_security.AgentRuntimeAuth()

        principal = auth.authenticate(request)

        self.assertIsNotNone(principal)
        self.assertEqual(principal.mode, "global-token")
        self.assertIsNone(principal.server_id)

    @override_settings(KEYWARDEN_AGENT_RUNTIME_ALLOW_TOKEN_FALLBACK=False)
    def test_agent_runtime_auth_can_disable_token_fallback(self):
        server_token = "server-token-strict-123"
        Server.objects.create(
            display_name="token-fallback-off-1",
            hostname="token-fallback-off-1.example.test",
            agent_api_token_hash=api_security.hash_agent_token(server_token),
        )
        request = SimpleNamespace(
            META={"HTTP_AUTHORIZATION": f"Bearer {server_token}"},
            path="/api/v1/agent/servers/1/log-config",
        )
        auth = api_security.AgentRuntimeAuth()

        principal = auth.authenticate(request)

        self.assertIsNone(principal)

    def test_sanitize_username_and_render_system_username(self):
        self.assertEqual(sanitize_username("Alice Smith"), "alice_smith")
        self.assertEqual(sanitize_username("  "), "")
        with override_settings(KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE="{{username}}--{{user_id}}"):
            rendered = render_system_username("Alice Smith", 42)
        self.assertEqual(rendered, "alice_smith--42")

    def test_certificate_label_and_comment_helpers(self):
        self.assertEqual(key_certificates._sanitize_label(" Prod Key #1 "), "prod-key-1")
        self.assertEqual(key_certificates._sanitize_label("$$$"), "key")
        self.assertEqual(
            key_certificates._ensure_comment("ssh-ed25519 AAAA old", "new-comment"),
            "ssh-ed25519 AAAA new-comment",
        )
        self.assertEqual(
            key_certificates._ensure_comment("ssh-ed25519 AAAA", ""),
            "ssh-ed25519 AAAA",
        )

    def test_write_file_sets_mode(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            target = f"{tmpdir}/test.txt"
            key_certificates._write_file(target, "hello", 0o600)
            with open(target, "r", encoding="utf-8") as handle:
                self.assertEqual(handle.read(), "hello")

    def test_sign_public_key_raises_when_ca_material_missing(self):
        with self.assertRaises(RuntimeError):
            key_certificates._sign_public_key(
                ca_private_key="",
                ca_public_key="",
                public_key="ssh-ed25519 AAAA",
                identity="id",
                principal="alice",
                serial=1,
                validity_days=1,
                comment="c",
            )

    def test_sign_public_key_raises_when_ssh_keygen_missing(self):
        with patch("apps.keys.certificates.subprocess.run", side_effect=FileNotFoundError("missing")):
            with self.assertRaises(RuntimeError):
                key_certificates._sign_public_key(
                    ca_private_key="private",
                    ca_public_key="ssh-ed25519 AAAA",
                    public_key="ssh-ed25519 BBBB",
                    identity="id",
                    principal="alice",
                    serial=1,
                    validity_days=1,
                    comment="c",
                )

    def test_sign_public_key_happy_path_reads_generated_cert(self):
        def fake_run(cmd, check, capture_output):
            pubkey_path = cmd[-1]
            cert_path = pubkey_path[:-4] + "-cert.pub"
            with open(cert_path, "w", encoding="utf-8") as handle:
                handle.write("ssh-ed25519-cert-v01 AAAACERT")
            return SimpleNamespace(stderr=b"")

        with patch("apps.keys.certificates.subprocess.run", side_effect=fake_run):
            cert = key_certificates._sign_public_key(
                ca_private_key="private",
                ca_public_key="ssh-ed25519 AAAA",
                public_key="ssh-ed25519 BBBB",
                identity="id",
                principal="alice",
                serial=1,
                validity_days=1,
                comment="comment",
            )
        self.assertIn("AAAACERT", cert)

    def test_issue_certificate_for_key_updates_record(self):
        user = SimpleNamespace(id=5, username="alice")
        key = SimpleNamespace(id=77, user_id=5, user=user, name="Laptop key", public_key="ssh-ed25519 BBBB")
        fake_ca = SimpleNamespace(
            private_key="private",
            public_key="public",
            get_private_key=lambda: "private",
        )
        fake_cert = SimpleNamespace(id=9)
        with (
            patch("apps.keys.certificates.get_active_ca", return_value=fake_ca),
            patch("apps.keys.certificates._sign_public_key", return_value="ssh-ed25519-cert-v01 AAAACERT"),
            patch("apps.keys.certificates.secrets.randbits", return_value=42),
            patch("apps.keys.certificates.SSHCertificate.objects.update_or_create", return_value=(fake_cert, True)) as upsert,
        ):
            cert = key_certificates.issue_certificate_for_key(key)
        self.assertEqual(cert, fake_cert)
        upsert.assert_called_once()

    def test_revoke_certificate_for_key_marks_cert_revoked(self):
        cert = SimpleNamespace(revoke=Mock(), save=Mock())
        key = SimpleNamespace(certificate=cert)
        key_certificates.revoke_certificate_for_key(key)
        cert.revoke.assert_called_once()
        cert.save.assert_called_once_with(update_fields=["is_active", "revoked_at"])

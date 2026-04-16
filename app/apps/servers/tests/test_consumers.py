from __future__ import annotations

from django.test import SimpleTestCase, override_settings

from apps.servers.consumers import _build_ssh_command


class ShellSSHCommandTests(SimpleTestCase):
    def test_build_command_uses_default_remote_shell(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertEqual(command[-1], "/bin/bash")

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

    @override_settings(KEYWARDEN_SHELL_REMOTE_COMMAND='"/bin/bash -li')
    def test_build_command_tolerates_invalid_shell_quoting(self):
        command = _build_ssh_command(
            key_path="/tmp/session_key",
            cert_path="/tmp/session_key-cert.pub",
            username="alice",
            host="server.example.test",
        )
        self.assertEqual(command[-1], '"/bin/bash -li')

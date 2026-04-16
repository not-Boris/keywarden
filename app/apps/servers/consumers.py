from __future__ import annotations

import asyncio
import os
import secrets
import shlex
import shutil
import subprocess
import tempfile

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
from django.conf import settings
from django.utils import timezone

from apps.audit.matching import find_matching_event_type
from apps.audit.models import AuditEventType, AuditLog
from apps.audit.utils import (
    get_client_ip_from_scope,
    get_request_id_from_scope,
    get_user_agent_from_scope,
)
from apps.keys.certificates import get_active_ca, _sign_public_key
from apps.keys.utils import render_system_username
from apps.servers.models import Server, ServerAccount
from apps.servers.permissions import user_can_shell


class ShellConsumer(AsyncWebsocketConsumer):
    async def connect(self):
        # Initialize per-connection state; this consumer is stateful
        # across the WebSocket lifecycle.
        self.proc = None
        self.reader_task = None
        self.tempdir = None
        self.tempdir_path = ""
        self.ssh_started = False
        self.ssh_output_seen = False
        self.key_path = ""
        self.cert_path = ""
        self.system_username = ""
        self.shell_target = ""
        self.server_id: int | None = None

        # Reject unauthenticated connections before any side effects.
        user = self.scope.get("user")
        if not user or not getattr(user, "is_authenticated", False):
            await self.close(code=4401)
            return
        server_id = self.scope.get("url_route", {}).get("kwargs", {}).get("server_id")
        if not server_id:
            await self.close(code=4400)
            return
        # Resolve the server and enforce object-level permissions before
        # accepting the socket.
        server = await self._get_server(user, int(server_id))
        if not server:
            await self.close(code=4404)
            return
        self.server_id = server.id
        can_shell = await self._can_shell(user, server)
        if not can_shell:
            await self.close(code=4403)
            return
        # Resolve the per-user system account name and the best reachable host.
        system_username = await self._get_system_username(user, server)
        shell_target = server.hostname or server.ipv4 or server.ipv6
        if not system_username or not shell_target:
            await self.close(code=4400)
            return
        self.system_username = system_username
        self.shell_target = shell_target

        # Only accept the socket after all authn/authz checks have passed.
        await self.accept()
        # Audit the WebSocket connection as an explicit, opt-in event.
        await self._audit_websocket_event(user=user, action="connect", metadata={"server_id": server.id})
        await self.send(text_data="Connecting...\r\n")
        try:
            await self._start_ssh(user)
        except Exception:
            await self.send(text_data="Connection failed.\r\n")
            await self.close()

    async def disconnect(self, code):
        user = self.scope.get("user")
        if user and getattr(user, "is_authenticated", False):
            await self._audit_websocket_event(
                user=user,
                action="disconnect",
                metadata={"code": code, "server_id": self.server_id},
            )
        if self.reader_task:
            self.reader_task.cancel()
            self.reader_task = None
        if self.proc and self.proc.returncode is None:
            self.proc.terminate()
            try:
                await asyncio.wait_for(self.proc.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self.proc.kill()
        if self.tempdir_path and self.ssh_started:
            if not _is_truthy(getattr(settings, "KEYWARDEN_SHELL_PRESERVE_TMP", False)):
                shutil.rmtree(self.tempdir_path, ignore_errors=True)
                self.tempdir_path = ""
        self.tempdir = None

    async def receive(self, text_data=None, bytes_data=None):
        if not self.proc or not self.proc.stdin:
            return
        # Forward WebSocket payloads directly to the SSH subprocess stdin.
        if bytes_data is not None:
            data = bytes_data
        elif text_data is not None:
            data = text_data.encode("utf-8")
        else:
            return
        if data:
            self.proc.stdin.write(data)
            await self.proc.stdin.drain()

    async def _start_ssh(self, user):
        # Generate a short-lived keypair + SSH certificate and then
        # bridge the WebSocket to an SSH subprocess.
        # Prefer tmpfs when available so the private key never hits disk.
        temp_base = "/dev/shm" if os.path.isdir("/dev/shm") and os.access("/dev/shm", os.W_OK) else None
        self.tempdir_path = tempfile.mkdtemp(prefix="keywarden-shell-", dir=temp_base)
        key_path, cert_path = await asyncio.to_thread(
            _generate_session_keypair,
            self.tempdir_path,
            user,
            self.system_username,
        )
        self.key_path = key_path
        self.cert_path = cert_path
        ssh_host = _format_ssh_host(self.shell_target)
        # Build a locked-down SSH invocation and explicitly launch a remote shell.
        command = _build_ssh_command(
            key_path=key_path,
            cert_path=cert_path,
            username=self.system_username,
            host=ssh_host,
        )
        self.proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.ssh_started = True
        self.reader_task = asyncio.create_task(self._stream_output())

    async def _stream_output(self):
        if not self.proc or not self.proc.stdout:
            return
        # Pump subprocess output until EOF, then close the socket.
        while True:
            chunk = await self.proc.stdout.read(4096)
            if not chunk:
                break
            self.ssh_output_seen = True
            await self.send(bytes_data=chunk)
        if self.proc:
            exit_code = await self.proc.wait()
            if exit_code != 0 and not self.ssh_output_seen:
                if _is_truthy(getattr(settings, "KEYWARDEN_SHELL_DEBUG", False)):
                    await self._send_ssh_failure_diagnostics(exit_code)
                else:
                    await self.send(
                        text_data=(
                            f"\r\nSSH exited with status {exit_code}. "
                            "Verify host reachability, username, and SSH CA trust.\r\n"
                        )
                    )
        await self.close()

    async def _send_ssh_failure_diagnostics(self, exit_code: int) -> None:
        lines = [
            (
                f"\r\nSSH exited with status {exit_code}. "
                "Verify host reachability, username, and SSH CA trust.\r\n"
            ),
            f"Target: {self.system_username}@{self.shell_target}\r\n",
        ]
        if self.tempdir_path and _is_truthy(getattr(settings, "KEYWARDEN_SHELL_PRESERVE_TMP", False)):
            lines.append(f"Session key material preserved at: {self.tempdir_path}\r\n")
        cert_info = await self._inspect_session_certificate()
        if cert_info:
            lines.append("\r\nSession certificate details:\r\n")
            lines.append(cert_info)
            lines.append("\r\n")
        diagnostic = await self._run_ssh_probe()
        if diagnostic:
            lines.append("\r\nSSH probe output:\r\n")
            lines.append(diagnostic)
            lines.append("\r\n")
        await self.send(text_data="".join(lines))

    async def _inspect_session_certificate(self) -> str:
        if not self.cert_path:
            return ""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ssh-keygen",
                "-L",
                "-f",
                self.cert_path,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception:
            return ""
        output, _ = await proc.communicate()
        if not output:
            return ""
        text = output.decode("utf-8", "ignore").strip()
        if not text:
            return ""
        return _truncate_lines(text, max_lines=20, max_chars=2000)

    async def _run_ssh_probe(self) -> str:
        if not self.key_path or not self.cert_path or not self.system_username or not self.shell_target:
            return ""
        probe_command = _build_ssh_command(
            key_path=self.key_path,
            cert_path=self.cert_path,
            username=self.system_username,
            host=_format_ssh_host(self.shell_target),
            remote_command="true",
            force_tty=False,
            log_level="DEBUG1",
            connect_timeout=8,
        )
        probe_command.insert(1, "-v")
        try:
            proc = await asyncio.create_subprocess_exec(
                *probe_command,
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
        except Exception:
            return ""
        timeout = int(getattr(settings, "KEYWARDEN_SHELL_DIAG_TIMEOUT_SECONDS", 10))
        timeout = max(1, timeout)
        try:
            output, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            return f"(probe timed out after {timeout}s)"
        if not output:
            return f"(probe exited with status {proc.returncode} and no output)"
        text = output.decode("utf-8", "ignore").strip()
        if not text:
            return f"(probe exited with status {proc.returncode} and no output)"
        return _summarize_probe_output(text)

    @database_sync_to_async
    def _get_server(self, user, server_id: int):
        try:
            server = Server.objects.get(id=server_id)
        except Server.DoesNotExist:
            return None
        if not user.has_perm("servers.view_server", server):
            return None
        return server

    @database_sync_to_async
    def _can_shell(self, user, server) -> bool:
        return user_can_shell(user, server, timezone.now())

    @database_sync_to_async
    def _get_system_username(self, user, server) -> str:
        account = ServerAccount.objects.filter(server=server, user=user).first()
        if account:
            return account.system_username
        return render_system_username(user.username, user.id)

    @database_sync_to_async
    def _audit_websocket_event(self, user, action: str, metadata: dict | None = None) -> None:
        try:
            path = str(self.scope.get("path") or "")
            client_ip = get_client_ip_from_scope(self.scope)
            # Match only against explicitly configured WebSocket event types.
            event_type = find_matching_event_type(
                kind=AuditEventType.Kind.WEBSOCKET,
                method="GET",
                route=path,
                path=path,
                ip=client_ip,
            )
            if event_type is None:
                return
            combined_metadata = {
                "action": action,
                "path": path,
            }
            if metadata:
                combined_metadata.update(metadata)
            AuditLog.objects.create(
                created_at=timezone.now(),
                actor=user,
                event_type=event_type,
                message=f"WebSocket {action} {path}",
                severity=event_type.default_severity,
                source=AuditLog.Source.API,
                ip_address=client_ip,
                user_agent=get_user_agent_from_scope(self.scope),
                request_id=get_request_id_from_scope(self.scope),
                metadata=combined_metadata,
            )
        except Exception:
            # Auditing is best-effort; never fail the shell session.
            return


def _generate_session_keypair(tempdir: str, user, principal: str) -> tuple[str, str]:
    # Create an ephemeral SSH keypair and sign it with the active CA so
    # the user gets time-scoped shell access without long-lived keys.
    ca = get_active_ca(created_by=user)
    serial = secrets.randbits(63)
    identity = f"keywarden-shell-{user.id}-{serial}"
    key_path = os.path.join(tempdir, "session_key")
    cmd = [
        "ssh-keygen",
        "-t",
        "ed25519",
        "-f",
        key_path,
        "-C",
        identity,
        "-N",
        "",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True)
    except FileNotFoundError as exc:
        raise RuntimeError("ssh-keygen not available") from exc
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"ssh-keygen failed: {exc.stderr.decode('utf-8', 'ignore')}") from exc
    # Restrict filesystem access to the private key.
    os.chmod(key_path, 0o600)
    pubkey_path = key_path + ".pub"
    with open(pubkey_path, "r", encoding="utf-8") as handle:
        public_key = handle.read().strip()
    cert_text = _sign_public_key(
        ca_private_key=ca.private_key,
        ca_public_key=ca.public_key,
        public_key=public_key,
        identity=identity,
        principal=principal,
        serial=serial,
        validity_days=1,
        validity_override=f"+{settings.KEYWARDEN_SHELL_CERT_VALIDITY_MINUTES}m",
        comment=identity,
    )
    cert_path = key_path + "-cert.pub"
    with open(cert_path, "w", encoding="utf-8") as handle:
        handle.write(cert_text + "\n")
    # Public cert is safe to be world-readable.
    os.chmod(cert_path, 0o644)
    return key_path, cert_path


def _format_ssh_host(host: str) -> str:
    # IPv6 hosts must be wrapped in brackets for the SSH CLI.
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host


def _build_ssh_command(
    *,
    key_path: str,
    cert_path: str,
    username: str,
    host: str,
    remote_command: str | None = None,
    force_tty: bool = True,
    log_level: str = "ERROR",
    connect_timeout: int | None = None,
) -> list[str]:
    command = [
        "ssh",
    ]
    if force_tty:
        command.append("-tt")
    command.extend(
        [
            "-i",
            key_path,
            "-o",
            f"CertificateFile={cert_path}",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ChallengeResponseAuthentication=no",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "VerifyHostKeyDNS=no",
            "-o",
            f"LogLevel={log_level}",
        ]
    )
    if connect_timeout is not None:
        command.extend(["-o", f"ConnectTimeout={connect_timeout}"])
    command.append(f"{username}@{host}")
    if remote_command is None:
        remote_command = str(getattr(settings, "KEYWARDEN_SHELL_REMOTE_COMMAND", "/bin/bash")).strip()
    else:
        remote_command = str(remote_command).strip()
    if not remote_command:
        return command
    try:
        remote_argv = shlex.split(remote_command)
    except ValueError:
        remote_argv = [remote_command]
    if remote_argv:
        command.extend(remote_argv)
    return command


def _is_truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _truncate_lines(text: str, *, max_lines: int, max_chars: int) -> str:
    if not text:
        return ""
    clipped = text[:max_chars]
    lines = clipped.splitlines()
    if len(lines) > max_lines:
        head_count = max(1, max_lines // 2)
        tail_count = max(1, max_lines - head_count)
        lines = (
            lines[:head_count]
            + ["... (middle omitted) ..."]
            + lines[-tail_count:]
        )
    if len(text) > max_chars:
        lines.append("... (truncated by size)")
    return "\n".join(lines)


def _summarize_probe_output(text: str) -> str:
    if not text:
        return ""
    lines = text.splitlines()
    lower_text = text.lower()
    causes = []
    if "account has expired" in lower_text:
        causes.append("Remote Linux account is expired.")
    if "permission denied (publickey" in lower_text or "permission denied" in lower_text:
        causes.append("SSH authentication was denied by server policy.")
    if "no such user" in lower_text:
        causes.append("Remote user account does not exist.")
    if "certificate invalid" in lower_text or "invalid certificate" in lower_text:
        causes.append("SSH certificate was rejected by the server.")
    keywords = (
        "authenticating to",
        "offering public key",
        "offering publickey",
        "server accepts key",
        "sign_and_send_pubkey",
        "authentications that can continue",
        "permission denied",
        "authentication succeeded",
        "received disconnect",
        "userauth",
        "certificate",
        "principal",
        "no such user",
        "account is locked",
    )
    interesting = []
    for line in lines:
        lower = line.lower()
        if any(keyword in lower for keyword in keywords):
            interesting.append(line)
    out = []
    if causes:
        out.append("Detected cause:")
        for cause in causes:
            out.append(f"- {cause}")
        out.append("")
    if interesting:
        out.append("Auth highlights:")
        out.extend(interesting[-30:])
    if lines:
        out.append("")
        out.append("Probe tail:")
        out.extend(lines[-20:])
    return _truncate_lines("\n".join(out), max_lines=80, max_chars=8000)

from __future__ import annotations

import asyncio
import os
import secrets
import subprocess
import tempfile

from channels.db import database_sync_to_async
from channels.generic.websocket import AsyncWebsocketConsumer
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
        self.system_username = ""
        self.shell_target = ""
        self.server_id: int | None = None

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
        system_username = await self._get_system_username(user, server)
        shell_target = server.hostname or server.ipv4 or server.ipv6
        if not system_username or not shell_target:
            await self.close(code=4400)
            return
        self.system_username = system_username
        self.shell_target = shell_target

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
        if self.tempdir:
            self.tempdir.cleanup()
            self.tempdir = None

    async def receive(self, text_data=None, bytes_data=None):
        if not self.proc or not self.proc.stdin:
            return
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
        self.tempdir = tempfile.TemporaryDirectory(prefix="keywarden-shell-")
        key_path, cert_path = await asyncio.to_thread(
            _generate_session_keypair,
            self.tempdir.name,
            user,
            self.system_username,
        )
        ssh_host = _format_ssh_host(self.shell_target)
        command = [
            "ssh",
            "-tt",
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
            "LogLevel=ERROR",
            f"{self.system_username}@{ssh_host}",
            "/bin/bash",
        ]
        self.proc = await asyncio.create_subprocess_exec(
            *command,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        self.reader_task = asyncio.create_task(self._stream_output())

    async def _stream_output(self):
        if not self.proc or not self.proc.stdout:
            return
        while True:
            chunk = await self.proc.stdout.read(4096)
            if not chunk:
                break
            await self.send(bytes_data=chunk)
        await self.close()

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
        comment=identity,
    )
    cert_path = key_path + "-cert.pub"
    with open(cert_path, "w", encoding="utf-8") as handle:
        handle.write(cert_text + "\n")
    os.chmod(cert_path, 0o644)
    return key_path, cert_path


def _format_ssh_host(host: str) -> str:
    # IPv6 hosts must be wrapped in brackets for the SSH CLI.
    if ":" in host and not (host.startswith("[") and host.endswith("]")):
        return f"[{host}]"
    return host

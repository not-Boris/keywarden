from __future__ import annotations

import os
import secrets

from django.conf import settings


DEFAULT_SECRET_DIR = "/var/lib/keywarden/ca-keys"


def secret_dir() -> str:
    path = str(getattr(settings, "KEYWARDEN_CA_KEY_DIR", DEFAULT_SECRET_DIR) or "").strip()
    if not path:
        path = DEFAULT_SECRET_DIR
    os.makedirs(path, mode=0o700, exist_ok=True)
    try:
        os.chmod(path, 0o700)
    except PermissionError:
        # Best-effort hardening when process owner cannot change mode.
        pass
    return path


def looks_like_pem(value: str) -> bool:
    return str(value or "").lstrip().startswith("-----BEGIN ")


def secret_ref_for(path: str) -> str:
    return f"file://{path}"


def parse_secret_ref(value: str) -> str:
    text = str(value or "").strip()
    if text.lower().startswith("file://"):
        return text[7:]
    return ""


def write_secret_file(prefix: str, payload: str) -> str:
    target_dir = secret_dir()
    token = secrets.token_hex(16)
    path = os.path.join(target_dir, f"{prefix}-{token}.pem")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(payload)
    os.chmod(path, 0o600)
    return secret_ref_for(path)


def read_secret_ref(value: str, *, label: str) -> str:
    path = parse_secret_ref(value)
    if not path:
        return ""
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read()
    except FileNotFoundError as exc:
        raise RuntimeError(f"{label} file missing: {path}") from exc
    except OSError as exc:
        raise RuntimeError(f"{label} file unreadable: {path}") from exc

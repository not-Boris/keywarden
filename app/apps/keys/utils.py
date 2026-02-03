from __future__ import annotations

import re

from django.conf import settings

MAX_USERNAME_LEN = 32
_SANITIZE_RE = re.compile(r"[^a-z0-9_-]")


def render_system_username(username: str, user_id: int) -> str:
    # Render from template and then sanitize to an OS-safe username.
    template = settings.KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE
    raw = template.replace("{{username}}", username or "")
    raw = raw.replace("{{user_id}}", str(user_id))
    cleaned = sanitize_username(raw)
    if len(cleaned) > MAX_USERNAME_LEN:
        cleaned = cleaned[:MAX_USERNAME_LEN]
    if cleaned:
        return cleaned
    # Fall back to a deterministic, non-empty username.
    return f"kw_{user_id}"


def sanitize_username(raw: str) -> str:
    # Normalize to lowercase and replace disallowed characters.
    raw = (raw or "").lower()
    raw = _SANITIZE_RE.sub("_", raw)
    raw = raw.strip("-_")
    if raw.startswith("-"):
        # Avoid leading dash, which can be interpreted as a CLI flag.
        return "kw" + raw
    return raw

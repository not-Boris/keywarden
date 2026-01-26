from __future__ import annotations

from typing import List, Optional

from django.contrib.auth import get_user_model
import hashlib

from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest, HttpResponse
from django.utils import timezone
from guardian.shortcuts import get_objects_for_user
from ninja import Query, Router, Schema
from ninja.errors import HttpError
from pydantic import Field

from apps.core.rbac import require_authenticated
from apps.keys.certificates import issue_certificate_for_key, revoke_certificate_for_key
from apps.keys.models import SSHCertificate, SSHKey


class KeyCreateIn(Schema):
    name: str
    public_key: str
    user_id: Optional[int] = None


class KeyUpdateIn(Schema):
    name: Optional[str] = None
    is_active: Optional[bool] = None


class KeyOut(Schema):
    id: int
    user_id: int
    name: str
    public_key: str
    key_type: str
    fingerprint: str
    is_active: bool
    created_at: str
    revoked_at: Optional[str] = None


class CertificateOut(Schema):
    key_id: int
    serial: int
    valid_after: str
    valid_before: str
    principals: List[str]


class KeysQuery(Schema):
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0)
    user_id: Optional[int] = None


def _key_to_out(key: SSHKey) -> KeyOut:
    return KeyOut(
        id=key.id,
        user_id=key.user_id,
        name=key.name,
        public_key=key.public_key,
        key_type=key.key_type,
        fingerprint=key.fingerprint,
        is_active=key.is_active,
        created_at=key.created_at.isoformat(),
        revoked_at=key.revoked_at.isoformat() if key.revoked_at else None,
    )


def _ensure_certificate(key: SSHKey, request_user) -> SSHCertificate:
    if not key.is_active:
        raise HttpError(409, "Key is revoked")
    now = timezone.now()
    try:
        cert = key.certificate
    except SSHCertificate.DoesNotExist:
        return issue_certificate_for_key(key, created_by=request_user)
    if not cert.is_active or cert.valid_before <= now:
        return issue_certificate_for_key(key, created_by=request_user)
    return cert


def _has_global_perm(request: HttpRequest, perm: str) -> bool:
    user = request.user
    return bool(user and user.has_perm(perm))


def build_router() -> Router:
    router = Router()

    @router.get("/", response=List[KeyOut])
    def list_keys(request: HttpRequest, filters: KeysQuery = Query(...)):
        """List SSH keys with pagination and filters.

        Auth: required.
        Permissions:
        - If user has global `keys.view_sshkey`, returns all keys.
        - Otherwise, returns only objects with `keys.view_sshkey` object permission.
        Filter: user_id (honored only with global view).
        Rationale: powers the key inventory UI and lets admins audit key usage.
        """
        require_authenticated(request)
        user = request.user
        if _has_global_perm(request, "keys.view_sshkey"):
            qs = SSHKey.objects.all()
        else:
            qs = get_objects_for_user(
                user,
                "keys.view_sshkey",
                klass=SSHKey,
                accept_global_perms=False,
            )
        qs = qs.order_by("-created_at")
        if filters.user_id and _has_global_perm(request, "keys.view_sshkey"):
            qs = qs.filter(user_id=filters.user_id)
        qs = qs[filters.offset : filters.offset + filters.limit]
        return [_key_to_out(key) for key in qs]

    @router.post("/", response=KeyOut)
    def create_key(request: HttpRequest, payload: KeyCreateIn):
        """Create an SSH public key.

        Auth: required.
        Permissions: requires global `keys.add_sshkey`.
        Rules:
        - Default owner is the current user.
        - If caller has global `keys.add_sshkey` and `keys.view_sshkey`, they may specify user_id.
        Side effects: grants owner object perms on the new key.
        Rationale: keys are the core authorization material synced to servers.
        """
        require_authenticated(request)
        if not request.user.has_perm("keys.add_sshkey"):
            raise HttpError(403, "Forbidden")
        is_admin = _has_global_perm(request, "keys.add_sshkey") and _has_global_perm(
            request, "keys.view_sshkey"
        )
        owner = request.user
        if is_admin and payload.user_id:
            User = get_user_model()
            try:
                owner = User.objects.get(id=payload.user_id)
            except User.DoesNotExist:
                raise HttpError(404, "User not found")
        elif payload.user_id and payload.user_id != request.user.id:
            raise HttpError(403, "Forbidden")
        name = (payload.name or "").strip()
        if not name:
            raise HttpError(422, {"name": ["Name cannot be empty."]})
        key = SSHKey(user=owner, name=name)
        try:
            key.set_public_key(payload.public_key)
        except ValidationError as exc:
            raise HttpError(422, {"public_key": [str(exc)]})
        try:
            with transaction.atomic():
                key.save()
                issue_certificate_for_key(key, created_by=request.user)
        except IntegrityError:
            raise HttpError(422, {"public_key": ["Key already exists."]})
        except Exception as exc:
            raise HttpError(500, {"detail": f"Certificate issuance failed: {exc}"})
        return _key_to_out(key)

    @router.get("/{key_id}", response=KeyOut)
    def get_key(request: HttpRequest, key_id: int):
        """Get a specific SSH key by id.

        Auth: required.
        Permissions: requires `keys.view_sshkey` on the object.
        Rationale: used by key detail views and server access debugging.
        """
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.view_sshkey", key):
            raise HttpError(403, "Forbidden")
        return _key_to_out(key)

    @router.post("/{key_id}/certificate", response=CertificateOut)
    def issue_certificate(request: HttpRequest, key_id: int):
        """Issue or re-issue an SSH certificate for a key.

        Auth: required.
        Permissions: requires `keys.view_sshkey` on the object.
        Rationale: allows users to download a fresh certificate as needed.
        """
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.view_sshkey", key):
            raise HttpError(403, "Forbidden")
        cert = issue_certificate_for_key(key, created_by=request.user)
        return CertificateOut(
            key_id=key.id,
            serial=cert.serial,
            valid_after=cert.valid_after.isoformat(),
            valid_before=cert.valid_before.isoformat(),
            principals=list(cert.principals or []),
        )

    @router.get("/{key_id}/certificate")
    def download_certificate(request: HttpRequest, key_id: int):
        """Download the SSH certificate for a key."""
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.view_sshkey", key):
            raise HttpError(403, "Forbidden")
        cert = _ensure_certificate(key, request.user)
        filename = f"keywarden-{key.user_id}-{key.id}-cert.pub"
        response = HttpResponse(cert.certificate, content_type="text/plain")
        response["Content-Disposition"] = f'attachment; filename="{filename}"'
        return response

    @router.get("/{key_id}/certificate.sha256")
    def download_certificate_hash(request: HttpRequest, key_id: int):
        """Download the SSH certificate hash for a key."""
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.view_sshkey", key):
            raise HttpError(403, "Forbidden")
        cert = _ensure_certificate(key, request.user)
        filename = f"keywarden-{key.user_id}-{key.id}-cert.pub"
        digest = hashlib.sha256(cert.certificate.encode("utf-8")).hexdigest()
        payload = f"{digest}  {filename}\n"
        response = HttpResponse(payload, content_type="text/plain")
        response["Content-Disposition"] = f'attachment; filename="{filename}.sha256"'
        return response

    @router.patch("/{key_id}", response=KeyOut)
    def update_key(request: HttpRequest, key_id: int, payload: KeyUpdateIn):
        """Update key name or active state.

        Auth: required.
        Permissions: requires `keys.change_sshkey` on the object.
        Rationale: allows key rotation and revocation without deletion.
        """
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.change_sshkey", key):
            raise HttpError(403, "Forbidden")
        if payload.name is None and payload.is_active is None:
            raise HttpError(422, {"detail": "No fields provided."})
        if payload.name is not None:
            name = payload.name.strip()
            if not name:
                raise HttpError(422, {"name": ["Name cannot be empty."]})
            key.name = name
        if payload.is_active is not None:
            key.is_active = payload.is_active
            if payload.is_active:
                key.revoked_at = None
                try:
                    issue_certificate_for_key(key, created_by=request.user)
                except Exception as exc:
                    raise HttpError(500, {"detail": f"Certificate issuance failed: {exc}"})
            else:
                key.revoked_at = timezone.now()
                revoke_certificate_for_key(key)
        key.save()
        return _key_to_out(key)

    @router.delete("/{key_id}", response={204: None})
    def delete_key(request: HttpRequest, key_id: int):
        """Revoke (soft delete) an SSH key.

        Auth: required.
        Permissions: requires `keys.delete_sshkey` on the object.
        Behavior: sets is_active false and revoked_at if key is active.
        Rationale: removes key access while preserving auditability.
        """
        require_authenticated(request)
        try:
            key = SSHKey.objects.get(id=key_id)
        except SSHKey.DoesNotExist:
            raise HttpError(404, "Not Found")
        if not request.user.has_perm("keys.delete_sshkey", key):
            raise HttpError(403, "Forbidden")
        if key.is_active:
            key.is_active = False
            key.revoked_at = timezone.now()
            key.save(update_fields=["is_active", "revoked_at"])
            revoke_certificate_for_key(key)
        return 204, None

    return router


router = build_router()

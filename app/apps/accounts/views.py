from datetime import timedelta
from django.conf import settings
from django.contrib import messages
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.core import signing
from django.core.mail import send_mail
from django.db import IntegrityError
from django.shortcuts import redirect, render
from django.template.loader import render_to_string
from django.urls import reverse, reverse_lazy
from django.utils import timezone
from urllib.parse import urlparse

from apps.keys.certificates import issue_certificate_for_key
from apps.keys.models import SSHKey

from .forms import ErasureRequestForm, NativePasswordResetForm, SSHKeyForm, StyledSetPasswordForm
from .identity import normalize_email
from .models import ErasureRequest, ExternalIdentity, NativeAccountSecurity

_EMAIL_VERIFICATION_SIGNER_SALT = "accounts.native-email-verification"


def _unlink_social_account(user, provider_id: str) -> None:
  try:
    from allauth.socialaccount.models import SocialAccount
  except Exception:
    return
  SocialAccount.objects.filter(user=user, provider=provider_id).delete()


def _has_sso_identity(user) -> bool:
  return ExternalIdentity.objects.filter(user=user).exists()


def _idp_account_portal_url() -> str:
  explicit = (getattr(settings, "KEYWARDEN_IDP_ACCOUNT_PORTAL_URL", "") or "").strip()
  if explicit:
    return explicit

  issuer = (getattr(settings, "KEYWARDEN_OIDC_ISSUER", "") or "").strip()
  if issuer:
    return issuer

  endpoint = (
    getattr(settings, "OIDC_OP_AUTHORIZATION_ENDPOINT", "")
    or getattr(settings, "OIDC_OP_DISCOVERY_ENDPOINT", "")
    or ""
  )
  if not endpoint:
    return ""
  parsed = urlparse(endpoint)
  if not parsed.scheme or not parsed.netloc:
    return ""
  return f"{parsed.scheme}://{parsed.netloc}/"


def _issue_email_verification_token(user) -> str:
  payload = {"uid": user.pk, "email": normalize_email(user.email)}
  return signing.dumps(payload, salt=_EMAIL_VERIFICATION_SIGNER_SALT)


def _resolve_email_verification_token(token: str):
  max_age = int(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_TOKEN_MAX_AGE_SECONDS", 86400))
  payload = signing.loads(token, salt=_EMAIL_VERIFICATION_SIGNER_SALT, max_age=max_age)
  user_id = payload.get("uid")
  email = normalize_email(payload.get("email"))
  if not user_id or not email:
    raise signing.BadSignature("Invalid token payload.")
  return user_id, email


def _oidc_provider_label() -> str:
  endpoint = (
    getattr(settings, "OIDC_OP_AUTHORIZATION_ENDPOINT", "")
    or getattr(settings, "OIDC_OP_DISCOVERY_ENDPOINT", "")
    or getattr(settings, "OIDC_OP_USER_ENDPOINT", "")
    or ""
  )
  if not endpoint:
    return "Identity Provider"
  parsed = urlparse(endpoint)
  host = (parsed.hostname or "").strip().lower()
  if not host:
    return "Identity Provider"
  parts = [part for part in host.split(".") if part and part != "www"]
  if len(parts) >= 2:
    return parts[-2].replace("-", " ").title()
  return host.replace("-", " ").title()


@login_required(login_url="/accounts/login/")
def profile(request):
  erasure_request = (
    ErasureRequest.objects.filter(user=request.user).order_by("-requested_at").first()
  )
  can_add_key = request.user.has_perm("keys.add_sshkey")
  if request.method == "POST":
    form_type = request.POST.get("form_type")
    if form_type == "ssh_key":
      erasure_form = ErasureRequestForm()
      key_form = SSHKeyForm(request.POST)
      if key_form.is_valid():
        if not can_add_key:
          key_form.add_error(None, "You do not have permission to add SSH keys.")
        else:
          name = key_form.cleaned_data["name"].strip()
          public_key = key_form.cleaned_data["public_key"].strip()
          key = SSHKey(user=request.user, name=name)
          try:
            key.set_public_key(public_key)
            key.save()
            issue_certificate_for_key(key, created_by=request.user)
            return redirect("accounts:profile")
          except ValidationError as exc:
            key_form.add_error("public_key", str(exc))
          except IntegrityError:
            key_form.add_error("public_key", "Key already exists.")
          except Exception:
            key_form.add_error(None, "Certificate issuance failed.")
    elif form_type == "unlink_github":
      key_form = SSHKeyForm()
      erasure_form = ErasureRequestForm()
      deleted_count, _ = ExternalIdentity.objects.filter(
        user=request.user,
        provider_type=ExternalIdentity.ProviderType.SOCIAL,
        provider_id__iexact="github",
      ).delete()
      _unlink_social_account(request.user, "github")
      if deleted_count:
        messages.success(request, "GitHub login was unlinked from your account.")
      else:
        messages.info(request, "No GitHub link was found on your account.")
      return redirect("accounts:profile")
    elif form_type == "send_email_verification":
      key_form = SSHKeyForm()
      erasure_form = ErasureRequestForm()
      idp_account_portal_url = _idp_account_portal_url()
      if _has_sso_identity(request.user):
        if idp_account_portal_url:
          messages.info(
            request,
            f"This account uses SSO. Verify your email in your identity provider: {idp_account_portal_url}",
          )
        else:
          messages.info(
            request,
            "This account uses SSO. Verify your email in your configured identity provider.",
          )
        return redirect("accounts:profile")

      if not bool(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_ENABLED", True)):
        messages.info(request, "Email verification is disabled in this environment.")
        return redirect("accounts:profile")

      security, _ = NativeAccountSecurity.objects.get_or_create(user=request.user)
      if security.email_verified:
        messages.success(request, "Your email is already verified.")
        return redirect("accounts:profile")

      cooldown_seconds = int(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_RESEND_COOLDOWN_SECONDS", 300))
      now = timezone.now()
      if (
        security.verification_email_sent_at
        and (now - security.verification_email_sent_at) < timedelta(seconds=cooldown_seconds)
      ):
        messages.info(
          request,
          f"Verification email recently sent. Please wait up to {cooldown_seconds} seconds before retrying.",
        )
        return redirect("accounts:profile")

      token = _issue_email_verification_token(request.user)
      verification_link = request.build_absolute_uri(
        reverse("accounts:email_verify", kwargs={"token": token})
      )
      context = {
        "user": request.user,
        "verification_link": verification_link,
        "expires_seconds": int(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_TOKEN_MAX_AGE_SECONDS", 86400)),
      }
      subject = render_to_string("accounts/email_verification_subject.txt", context).strip()
      body = render_to_string("accounts/email_verification_email.txt", context)
      try:
        send_mail(
          subject=subject,
          message=body,
          from_email=getattr(settings, "DEFAULT_FROM_EMAIL", "no-reply@localhost"),
          recipient_list=[request.user.email],
          fail_silently=False,
        )
      except Exception:
        messages.error(request, "Failed to send verification email. Contact an administrator.")
        return redirect("accounts:profile")
      security.verification_email_sent_at = now
      security.save(update_fields=["verification_email_sent_at", "updated_at"])
      messages.success(request, f"Verification email sent to {request.user.email}.")
      return redirect("accounts:profile")
    elif form_type == "erasure":
      key_form = SSHKeyForm()
      erasure_form = ErasureRequestForm(request.POST)
      if erasure_form.is_valid():
        if erasure_request and erasure_request.status == ErasureRequest.Status.PENDING:
          erasure_form.add_error(None, "You already have a pending erasure request.")
        else:
          ErasureRequest.objects.create(
            user=request.user,
            reason=erasure_form.cleaned_data["reason"].strip(),
          )
          return redirect("accounts:profile")
    else:
      key_form = SSHKeyForm()
      erasure_form = ErasureRequestForm()
  else:
    erasure_form = ErasureRequestForm()
    key_form = SSHKeyForm()

  ssh_keys = SSHKey.objects.filter(user=request.user).order_by("-created_at")
  external_identities = ExternalIdentity.objects.filter(user=request.user).order_by("-last_login_at", "provider_id")
  has_sso_identity = external_identities.exists()
  oidc_identity = external_identities.filter(provider_type=ExternalIdentity.ProviderType.OIDC).first()
  github_identity = external_identities.filter(
    provider_type=ExternalIdentity.ProviderType.SOCIAL,
    provider_id__iexact="github",
  ).first()
  github_provider = next(
    (
      provider
      for provider in getattr(settings, "KEYWARDEN_SOCIAL_LOGIN_PROVIDERS", [])
      if (provider.get("id", "").strip().lower() == "github")
    ),
    {},
  )
  github_login_url = github_provider.get("login_url", "")
  github_connect_url = github_provider.get("connect_url", "")
  if not github_connect_url and github_login_url:
    github_connect_url = f"{github_login_url}?process=connect"

  native_security = None
  if not has_sso_identity:
    native_security, _ = NativeAccountSecurity.objects.get_or_create(user=request.user)
  idp_account_portal_url = _idp_account_portal_url()

  context = {
    "user": request.user,
    "auth_mode": getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid"),
    "oidc_enabled": bool(getattr(settings, "KEYWARDEN_OIDC_LOGIN_ENABLED", False)),
    "oidc_identity": oidc_identity,
    "oidc_provider_id": getattr(settings, "KEYWARDEN_OIDC_PROVIDER_ID", "oidc"),
    "oidc_issuer": getattr(settings, "KEYWARDEN_OIDC_ISSUER", ""),
    "github_social_configured": bool(github_login_url),
    "github_social_connect_url": github_connect_url,
    "github_identity": github_identity,
    "native_account_security": native_security,
    "native_security_enabled": not has_sso_identity,
    "email_verification_enabled": bool(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_ENABLED", True)),
    "idp_account_portal_url": idp_account_portal_url,
    "erasure_request": erasure_request,
    "erasure_form": erasure_form,
    "key_form": key_form,
    "ssh_keys": ssh_keys,
    "can_add_key": can_add_key,
  }
  return render(request, "accounts/profile.html", context)


def login_view(request):
  auth_mode = getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid")
  oidc_login_enabled = bool(getattr(settings, "KEYWARDEN_OIDC_LOGIN_ENABLED", False))
  social_providers = (
    getattr(settings, "KEYWARDEN_SOCIAL_LOGIN_PROVIDERS", [])
    if auth_mode == "hybrid"
    else []
  )

  if auth_mode == "oidc" and oidc_login_enabled:
    return redirect("/oidc/authenticate/")

  has_sso_options = bool(
    oidc_login_enabled
    or social_providers
  )
  show_native_login = (
    request.method == "POST"
    or request.GET.get("native") == "1"
    or auth_mode == "native"
  )

  # native or hybrid -> render Django's built-in login view
  return auth_views.LoginView.as_view(
    template_name="accounts/login.html",
    extra_context={
      "social_providers": social_providers,
      "oidc_enabled": oidc_login_enabled,
      "oidc_login_url": "/oidc/authenticate/",
      "oidc_provider_label": _oidc_provider_label(),
      "show_native_login": show_native_login,
      "can_use_native_login": auth_mode in {"native", "hybrid"},
      "show_sso_choice": has_sso_options and not show_native_login,
      "password_reset_enabled": auth_mode in {"native", "hybrid"},
      "idp_account_portal_url": _idp_account_portal_url(),
    },
  )(request)


def logout_view(request):
  logout(request)
  return redirect(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))


def password_reset_view(request):
  return auth_views.PasswordResetView.as_view(
    template_name="accounts/password_reset_form.html",
    email_template_name="accounts/password_reset_email.txt",
    subject_template_name="accounts/password_reset_subject.txt",
    success_url=reverse_lazy("accounts:password_reset_done"),
    form_class=NativePasswordResetForm,
    extra_context={
      "idp_account_portal_url": _idp_account_portal_url(),
    },
  )(request)


def password_reset_done_view(request):
  return auth_views.PasswordResetDoneView.as_view(
    template_name="accounts/password_reset_done.html",
    extra_context={
      "idp_account_portal_url": _idp_account_portal_url(),
    },
  )(request)


def password_reset_confirm_view(request, uidb64, token):
  return auth_views.PasswordResetConfirmView.as_view(
    template_name="accounts/password_reset_confirm.html",
    success_url=reverse_lazy("accounts:password_reset_complete"),
    form_class=StyledSetPasswordForm,
  )(request, uidb64=uidb64, token=token)


def password_reset_complete_view(request):
  return auth_views.PasswordResetCompleteView.as_view(
    template_name="accounts/password_reset_complete.html",
  )(request)


def email_verify_view(request, token):
  if not bool(getattr(settings, "KEYWARDEN_EMAIL_VERIFICATION_ENABLED", True)):
    messages.info(request, "Email verification is disabled in this environment.")
    return redirect("accounts:login")

  try:
    user_id, token_email = _resolve_email_verification_token(token)
  except signing.SignatureExpired:
    messages.error(request, "This verification link has expired. Request a new email from your profile.")
    return redirect("accounts:login")
  except signing.BadSignature:
    messages.error(request, "Invalid verification link.")
    return redirect("accounts:login")

  user = (
    request.user
    if request.user.is_authenticated and request.user.pk == user_id
    else None
  )
  if user is None:
    from django.contrib.auth import get_user_model
    user = get_user_model().objects.filter(pk=user_id, is_active=True).first()
  if not user:
    messages.error(request, "Verification target account was not found.")
    return redirect("accounts:login")

  if _has_sso_identity(user):
    idp_account_portal_url = _idp_account_portal_url()
    if idp_account_portal_url:
      messages.info(
        request,
        f"This account is managed by SSO. Verify email at your identity provider: {idp_account_portal_url}",
      )
    else:
      messages.info(
        request,
        "This account is managed by SSO. Verify email at your identity provider.",
      )
    return redirect("accounts:profile" if request.user.is_authenticated else "accounts:login")

  if normalize_email(user.email) != token_email:
    messages.error(request, "Verification link does not match the current account email.")
    return redirect("accounts:login")

  security, _ = NativeAccountSecurity.objects.get_or_create(user=user)
  if not security.email_verified:
    security.email_verified = True
    security.email_verified_at = timezone.now()
    security.save(update_fields=["email_verified", "email_verified_at", "updated_at"])

  messages.success(request, "Your email address has been verified.")
  return redirect("accounts:profile" if request.user.is_authenticated else "accounts:login")

from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.shortcuts import redirect, render
from urllib.parse import urlparse

from apps.keys.certificates import issue_certificate_for_key
from apps.keys.models import SSHKey

from .forms import ErasureRequestForm, SSHKeyForm
from .models import ErasureRequest, ExternalIdentity


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
    else:
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
    erasure_form = ErasureRequestForm()
    key_form = SSHKeyForm()

  ssh_keys = SSHKey.objects.filter(user=request.user).order_by("-created_at")
  external_identities = ExternalIdentity.objects.filter(user=request.user).order_by("-last_login_at", "provider_id")
  oidc_identity = external_identities.filter(provider_type=ExternalIdentity.ProviderType.OIDC).first()
  social_identity_map = {
    identity.provider_id.lower(): identity
    for identity in external_identities.filter(provider_type=ExternalIdentity.ProviderType.SOCIAL)
  }
  configured_social_map = {
    provider.get("id", "").strip().lower(): provider
    for provider in getattr(settings, "KEYWARDEN_SOCIAL_LOGIN_PROVIDERS", [])
    if provider.get("id")
  }

  social_provider_defaults = [
    ("github", "GitHub"),
    ("google", "Google"),
    ("apple", "Apple"),
    ("gitlab", "GitLab"),
    ("microsoft", "Microsoft Entra ID"),
  ]
  social_provider_cards = []
  seen_provider_ids = set()
  for provider_id, provider_name in social_provider_defaults:
    provider_config = configured_social_map.get(provider_id, {})
    identity = social_identity_map.get(provider_id)
    social_provider_cards.append(
      {
        "id": provider_id,
        "name": provider_name,
        "configured": bool(provider_config.get("login_url")),
        "login_url": provider_config.get("login_url", ""),
        "linked": bool(identity),
        "identity": identity,
      }
    )
    seen_provider_ids.add(provider_id)

  for provider_id, provider_config in configured_social_map.items():
    if provider_id in seen_provider_ids:
      continue
    identity = social_identity_map.get(provider_id)
    social_provider_cards.append(
      {
        "id": provider_id,
        "name": provider_config.get("name", provider_id.title()),
        "configured": bool(provider_config.get("login_url")),
        "login_url": provider_config.get("login_url", ""),
        "linked": bool(identity),
        "identity": identity,
      }
    )

  context = {
    "user": request.user,
    "auth_mode": getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid"),
    "oidc_enabled": bool(getattr(settings, "KEYWARDEN_OIDC_LOGIN_ENABLED", False)),
    "oidc_identity": oidc_identity,
    "oidc_provider_id": getattr(settings, "KEYWARDEN_OIDC_PROVIDER_ID", "oidc"),
    "oidc_issuer": getattr(settings, "KEYWARDEN_OIDC_ISSUER", ""),
    "social_provider_cards": social_provider_cards,
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
    },
  )(request)


def logout_view(request):
  logout(request)
  return redirect(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))

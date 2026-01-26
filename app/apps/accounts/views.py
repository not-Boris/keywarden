from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.db import IntegrityError
from django.shortcuts import redirect, render

from apps.keys.certificates import issue_certificate_for_key
from apps.keys.models import SSHKey

from .forms import ErasureRequestForm, SSHKeyForm
from .models import ErasureRequest


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
  context = {
    "user": request.user,
    "auth_mode": getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid"),
    "erasure_request": erasure_request,
    "erasure_form": erasure_form,
    "key_form": key_form,
    "ssh_keys": ssh_keys,
    "can_add_key": can_add_key,
  }
  return render(request, "accounts/profile.html", context)


def login_view(request):
  auth_mode = getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid")
  if auth_mode == "oidc":
    return redirect("/oidc/authenticate/")
  # native or hybrid -> render Django's built-in login view
  return auth_views.LoginView.as_view(template_name="accounts/login.html")(request)


def logout_view(request):
  logout(request)
  return redirect(getattr(settings, "LOGOUT_REDIRECT_URL", "/"))

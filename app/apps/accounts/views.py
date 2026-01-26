from django.conf import settings
from django.contrib.auth import logout
from django.contrib.auth import views as auth_views
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from .forms import ErasureRequestForm
from .models import ErasureRequest


@login_required(login_url="/accounts/login/")
def profile(request):
  erasure_request = (
    ErasureRequest.objects.filter(user=request.user).order_by("-requested_at").first()
  )
  if request.method == "POST":
    form = ErasureRequestForm(request.POST)
    if form.is_valid():
      if erasure_request and erasure_request.status == ErasureRequest.Status.PENDING:
        form.add_error(None, "You already have a pending erasure request.")
      else:
        ErasureRequest.objects.create(
          user=request.user,
          reason=form.cleaned_data["reason"].strip(),
        )
        return redirect("accounts:profile")
  else:
    form = ErasureRequestForm()

  context = {
    "user": request.user,
    "auth_mode": getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid"),
    "erasure_request": erasure_request,
    "erasure_form": form,
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

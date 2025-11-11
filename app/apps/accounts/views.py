from django.contrib.auth.decorators import login_required
from django.shortcuts import render
from django.conf import settings
from django.shortcuts import redirect
from django.contrib.auth import views as auth_views
from django.contrib.auth import logout


@login_required(login_url="/accounts/login/")
def profile(request):
  context = {
    "user": request.user,
    "auth_mode": getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid"),
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


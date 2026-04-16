from django.urls import path
from . import views

app_name = "accounts"

urlpatterns = [
  path("login/", views.login_view, name="login"),
  path("logout/", views.logout_view, name="logout"),
  path("password-reset/", views.password_reset_view, name="password_reset"),
  path("password-reset/done/", views.password_reset_done_view, name="password_reset_done"),
  path(
    "password-reset/confirm/<uidb64>/<token>/",
    views.password_reset_confirm_view,
    name="password_reset_confirm",
  ),
  path("password-reset/complete/", views.password_reset_complete_view, name="password_reset_complete"),
  path("email/verify/<str:token>/", views.email_verify_view, name="email_verify"),
  path("profile/", views.profile, name="profile"),
]

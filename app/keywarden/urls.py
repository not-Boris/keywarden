from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from keywarden.api import api as ninja_api

urlpatterns = [
    path("admin/", admin.site.urls),
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("accounts/", include("apps.accounts.urls")),
    # API
    path("api/", ninja_api.urls),
    path("api/auth/jwt/create/", TokenObtainPairView.as_view(), name="jwt-create"),
    path("api/auth/jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    path("", RedirectView.as_view(pattern_name="accounts:login", permanent=False)),
]
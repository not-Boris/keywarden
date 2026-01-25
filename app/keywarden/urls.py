from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from keywarden.api import api as ninja_api, api_v1 as ninja_api_v1

urlpatterns = [
    path("admin/", admin.site.urls),
    path("oidc/", include("mozilla_django_oidc.urls")),
    path("accounts/", include("apps.accounts.urls")),
    path("servers/", include("apps.servers.urls")),
    # API
    path("api/", ninja_api.urls),
    path("api/v1/", ninja_api_v1.urls),
    path("api/auth/jwt/create/", TokenObtainPairView.as_view(), name="jwt-create"),
    path("api/auth/jwt/refresh/", TokenRefreshView.as_view(), name="jwt-refresh"),
    path("", RedirectView.as_view(pattern_name="servers:dashboard", permanent=False)),
]

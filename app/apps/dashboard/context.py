from django.conf import settings
from django.contrib.auth import get_user_model, models as auth_models


def dashboard_status(request):
    user_count = get_user_model().objects.count()
    group_count = auth_models.Group.objects.count()
    auth_mode = getattr(settings, "KEYWARDEN_AUTH_MODE", "hybrid")
    has_superuser = get_user_model().objects.filter(is_superuser=True).exists()
    oidc_configured = bool(
        getattr(settings, "OIDC_RP_CLIENT_ID", None)
        and getattr(settings, "OIDC_RP_CLIENT_SECRET", None)
        and getattr(settings, "OIDC_OP_AUTHORIZATION_ENDPOINT", None)
        and getattr(settings, "OIDC_OP_TOKEN_ENDPOINT", None)
        and getattr(settings, "OIDC_OP_USER_ENDPOINT", None)
        and getattr(settings, "OIDC_OP_JWKS_ENDPOINT", None)
    )

    return {
        "dashboard_status": {
            "auth_mode": auth_mode,
            "user_count": user_count,
            "group_count": group_count,
            "has_superuser": has_superuser,
            "oidc_configured": oidc_configured,
        }
    }



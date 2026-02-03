import os
from pathlib import Path
from dotenv import load_dotenv

from django.urls import reverse_lazy
from django.templatetags.static import static
from django.utils.translation import gettext_lazy as _

load_dotenv()

BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.getenv("KEYWARDEN_SECRET_KEY")
DEBUG = os.getenv("KEYWARDEN_DEBUG", "False")

ALLOWED_HOSTS = os.getenv("KEYWARDEN_ALLOWED_HOSTS", "").split(",")
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("KEYWARDEN_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True

INSTALLED_APPS = [
    "unfold.contrib.guardian",
    "unfold",               # Admin UI
    "unfold.contrib.filters",
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "channels",
    "guardian",
    "rest_framework",
    "apps.audit",
    "apps.accounts",
    "apps.core.apps.CoreConfig",
    "apps.dashboard",
    "apps.servers.apps.ServersConfig",
    "apps.keys.apps.KeysConfig",
    "apps.access.apps.AccessConfig",
    "apps.telemetry",
    "ninja",                # Django Ninja API
    "mozilla_django_oidc",   # OIDC Client
    "tailwind",
    "theme",
    "keywarden"
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "apps.audit.middleware.ApiAuditLogMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

# AUTHENTICATION_BACKENDS = [
#     "mozilla_django_oidc.auth.OIDCAuthenticationBackend",  # if you enabled OIDC
#     "django.contrib.auth.backends.ModelBackend",           # default Django auth
# ]

ROOT_URLCONF = "keywarden.urls"
WSGI_APPLICATION = "keywarden.wsgi.application"
ASGI_APPLICATION = "keywarden.asgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": os.getenv("KEYWARDEN_POSTGRES_DB", "keywarden"),
        "USER": os.getenv("KEYWARDEN_POSTGRES_USER", "keywarden"),
        "PASSWORD": os.getenv("KEYWARDEN_POSTGRES_PASSWORD", "postgres"),
        "HOST": os.getenv("KEYWARDEN_POSTGRES_HOST", "keywarden-db"),
        "PORT": os.getenv("KEYWARDEN_POSTGRES_PORT", "5432"),
    }
}

REDIS_URL = os.getenv("KEYWARDEN_REDIS_URL", "redis://127.0.0.1:6379/1")

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": REDIS_URL,
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
    }
}

CHANNEL_LAYERS = {
    "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"},
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

KEYWARDEN_AGENT_CERT_VALIDITY_DAYS = int(os.getenv("KEYWARDEN_AGENT_CERT_VALIDITY_DAYS", "90"))
KEYWARDEN_USER_CERT_VALIDITY_DAYS = int(os.getenv("KEYWARDEN_USER_CERT_VALIDITY_DAYS", "30"))
KEYWARDEN_SHELL_CERT_VALIDITY_MINUTES = int(os.getenv("KEYWARDEN_SHELL_CERT_VALIDITY_MINUTES", "15"))
KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE = os.getenv(
    "KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE", "{{username}}_{{user_id}}"
)

CELERY_BROKER_URL = os.getenv("KEYWARDEN_CELERY_BROKER_URL", REDIS_URL)
CELERY_RESULT_BACKEND = os.getenv("KEYWARDEN_CELERY_RESULT_BACKEND", REDIS_URL)
CELERY_ACCEPT_CONTENT = ["json"]
CELERY_TASK_SERIALIZER = "json"
CELERY_RESULT_SERIALIZER = "json"
CELERY_TIMEZONE = "UTC"
CELERY_BEAT_SCHEDULE = {
    "expire-access-requests": {
        "task": "apps.access.tasks.expire_access_requests",
        "schedule": 60.0,
    },
}

PASSWORD_HASHERS = [
    "django.contrib.auth.hashers.Argon2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2PasswordHasher",
    "django.contrib.auth.hashers.PBKDF2SHA1PasswordHasher",
    "django.contrib.auth.hashers.BCryptSHA256PasswordHasher",
    "django.contrib.auth.hashers.ScryptPasswordHasher",
]

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR/"static"
STATICFILES_STORAGE = "whitenoise.storage.CompressedManifestStaticFilesStorage"

TAILWIND_APP_NAME="theme"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {"context_processors": [
            "django.template.context_processors.debug",
            "django.template.context_processors.request",
            "django.contrib.auth.context_processors.auth",
            "django.contrib.messages.context_processors.messages",
            "apps.dashboard.context.dashboard_status",
        ]},
    },
]

# AUTHENTICATION_BACKENDS is configured dynamically below based on KEYWARDEN_AUTH_MODE

UNFOLD = {
    "SITE_ICON": lambda request: static("branding/keywarden-favicon.svg"),
    "SITE_LOGO": lambda request: static("branding/keywarden-favicon.svg"),
    "SITE_TITLE": "Admin - Keywarden",
    "SITE_HEADER": "Keywarden",
    "SITE_FAVICONS": [
        {
            "rel": "icon",
            "sizes": "32x32",
            "type": "image/svg+xml",
            "href": lambda request: static("branding/keywarden-favicon.svg"),
        },
    ],
    "SITE_DROPDOWN": [
        {
            "icon": "diamond",
            "title": _("Gitea"),
            "link": "https://git.ntbx.io/boris/keywarden",
        },
    ],
    "SHOW_HISTORY": True,
    "SITE_URL": "/",
    "LOGIN_REDIRECT_URL": "/admin/",
    "ENVIRONMENT": "Keywarden",
    "ENVIRONMENT_COLOR": "#7C3AED",
    "SHOW_VIEW_ON_SITE": True,
    "THEME": "dark", # Force theme: "dark" or "light". Will disable theme switcher
    "SIDEBAR": {
        "show_search": True,
        "show_all_applications": True,
        "navigation": [
            {
                "title": "Dashboard",
                "separator": True,
                "items": [
                    {
                        "title": "Dashboard",
                        "icon": "dashboard",
                        "link": "/admin/",
                    },
                ],
            },
        ],
    },
    "STYLES": [
        "/static/unfold/css/styles.css",
        "/static/unfold/css/simplebar.css",
        #(lambda request: "/static/unfold/css/keywarden.css"),
    ],
    # "TABS": [
    #     {
    #         "models": [
    #             "auth.User",
    #         ],
    #         "items": [
    #             {
    #                 "title": _("Logs"),
    #                 "link": reverse_lazy("admin:audit_auditlog_changelist"),
    #                 "attrs": {"hx-boost": "true"},
    #             },
    #             {
    #                 "title": _("Event Types"),
    #                 "link": reverse_lazy("admin:audit_auditeventtype_changelist"),
    #                 "attrs": {"hx-boost": "true"},
    #             },
    #         ],
    #     },
    #     {
    #         "models": [
    #             "servers.Server",
    #         ],
    #         "items": [
    #             {
    #                 "title": _("Servers"),
    #                 "link": reverse_lazy("admin:servers_server_changelist"),
    #                 "attrs": {"hx-boost": "true"},
    #             },
    #         ],
    #     },
    # ],    
}
MEDIA_URL = "/media/"
MEDIA_ROOT = BASE_DIR/"media"

OIDC_RP_CLIENT_ID = os.getenv("KEYWARDEN_OIDC_CLIENT_ID")
OIDC_RP_CLIENT_SECRET = os.getenv("KEYWARDEN_OIDC_CLIENT_SECRET")
OIDC_OP_AUTHORIZATION_ENDPOINT = os.getenv("KEYWARDEN_OIDC_AUTHORIZATION_ENDPOINT")
OIDC_OP_TOKEN_ENDPOINT = os.getenv("KEYWARDEN_OIDC_TOKEN_ENDPOINT")
OIDC_OP_USER_ENDPOINT = os.getenv("KEYWARDEN_OIDC_USER_ENDPOINT")
OIDC_OP_JWKS_ENDPOINT = os.getenv("KEYWARDEN_OIDC_JWKS_ENDPOINT")

# Auth mode: native | oidc | hybrid
AUTH_MODE = os.getenv("KEYWARDEN_AUTH_MODE", "hybrid").lower()
if AUTH_MODE not in {"native", "oidc", "hybrid"}:
    AUTH_MODE = "hybrid"
KEYWARDEN_AUTH_MODE = AUTH_MODE

if AUTH_MODE == "oidc":
    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
        "mozilla_django_oidc.auth.OIDCAuthenticationBackend",
    ]
    LOGIN_URL = "/oidc/authenticate/"
else:
    # native or hybrid -> allow both, native first for precedence
    AUTHENTICATION_BACKENDS = [
        "django.contrib.auth.backends.ModelBackend",
        "guardian.backends.ObjectPermissionBackend",
        "mozilla_django_oidc.auth.OIDCAuthenticationBackend",
    ]
    LOGIN_URL = "/accounts/login/"
LOGOUT_URL = "/oidc/logout/"
LOGIN_REDIRECT_URL = "/servers/"
LOGOUT_REDIRECT_URL = "/"

ANONYMOUS_USER_NAME = None

def permission_callback(request):
    return request.user.has_perm("keywarden.change_model")

import os
from pathlib import Path
from dotenv import load_dotenv

from django.urls import reverse_lazy
from django.templatetags.static import static
from django.utils.translation import gettext_lazy as _

# Load environment overrides early so settings can reference them.
load_dotenv()


def env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [item.strip() for item in raw.split(",") if item.strip()]


BASE_DIR = Path(__file__).resolve().parent.parent.parent

SECRET_KEY = os.getenv("KEYWARDEN_SECRET_KEY")
DEBUG = os.getenv("KEYWARDEN_DEBUG", "False")

ALLOWED_HOSTS = os.getenv("KEYWARDEN_ALLOWED_HOSTS", "").split(",")
CSRF_TRUSTED_ORIGINS = [
    origin.strip()
    for origin in os.getenv("KEYWARDEN_TRUSTED_ORIGINS", "").split(",")
    if origin.strip()
]

KEYWARDEN_SOCIAL_GOOGLE_CLIENT_ID = os.getenv("KEYWARDEN_SOCIAL_GOOGLE_CLIENT_ID", "").strip()
KEYWARDEN_SOCIAL_GOOGLE_CLIENT_SECRET = os.getenv("KEYWARDEN_SOCIAL_GOOGLE_CLIENT_SECRET", "").strip()
KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID = os.getenv("KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID", "").strip()
KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET = os.getenv("KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET", "").strip()
KEYWARDEN_SOCIAL_APPLE_CLIENT_ID = os.getenv("KEYWARDEN_SOCIAL_APPLE_CLIENT_ID", "").strip()
KEYWARDEN_SOCIAL_APPLE_CLIENT_SECRET = os.getenv("KEYWARDEN_SOCIAL_APPLE_CLIENT_SECRET", "").strip()

KEYWARDEN_SOCIAL_GOOGLE_ENABLED = env_bool(
    "KEYWARDEN_SOCIAL_GOOGLE_ENABLED",
    default=bool(KEYWARDEN_SOCIAL_GOOGLE_CLIENT_ID and KEYWARDEN_SOCIAL_GOOGLE_CLIENT_SECRET),
)
KEYWARDEN_SOCIAL_GITHUB_ENABLED = env_bool(
    "KEYWARDEN_SOCIAL_GITHUB_ENABLED",
    default=bool(KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID and KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET),
)
KEYWARDEN_SOCIAL_APPLE_ENABLED = env_bool(
    "KEYWARDEN_SOCIAL_APPLE_ENABLED",
    default=bool(KEYWARDEN_SOCIAL_APPLE_CLIENT_ID and KEYWARDEN_SOCIAL_APPLE_CLIENT_SECRET),
)

KEYWARDEN_SOCIAL_GOOGLE_CONFIGURED = bool(
    KEYWARDEN_SOCIAL_GOOGLE_ENABLED
    and KEYWARDEN_SOCIAL_GOOGLE_CLIENT_ID
    and KEYWARDEN_SOCIAL_GOOGLE_CLIENT_SECRET
)
KEYWARDEN_SOCIAL_GITHUB_CONFIGURED = bool(
    KEYWARDEN_SOCIAL_GITHUB_ENABLED
    and KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID
    and KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET
)
KEYWARDEN_SOCIAL_APPLE_CONFIGURED = bool(
    KEYWARDEN_SOCIAL_APPLE_ENABLED
    and KEYWARDEN_SOCIAL_APPLE_CLIENT_ID
    and KEYWARDEN_SOCIAL_APPLE_CLIENT_SECRET
)

KEYWARDEN_SOCIAL_AUTH_ENABLED = any(
    (
        KEYWARDEN_SOCIAL_GOOGLE_CONFIGURED,
        KEYWARDEN_SOCIAL_GITHUB_CONFIGURED,
        KEYWARDEN_SOCIAL_APPLE_CONFIGURED,
    )
)

# Default to secure cookies and respect TLS termination headers.
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

if KEYWARDEN_SOCIAL_AUTH_ENABLED:
    INSTALLED_APPS.extend(
        [
            "django.contrib.sites",
            "allauth",
            "allauth.account",
            "allauth.socialaccount",
        ]
    )
    if KEYWARDEN_SOCIAL_GOOGLE_CONFIGURED:
        INSTALLED_APPS.append("allauth.socialaccount.providers.google")
    if KEYWARDEN_SOCIAL_GITHUB_CONFIGURED:
        INSTALLED_APPS.append("allauth.socialaccount.providers.github")
    if KEYWARDEN_SOCIAL_APPLE_CONFIGURED:
        INSTALLED_APPS.append("allauth.socialaccount.providers.apple")

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

if KEYWARDEN_SOCIAL_AUTH_ENABLED:
    MIDDLEWARE.insert(
        MIDDLEWARE.index("django.contrib.auth.middleware.AuthenticationMiddleware") + 1,
        "allauth.account.middleware.AccountMiddleware",
    )

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

# In-memory channel layer keeps local development simple.
CHANNEL_LAYERS = {
    "default": {"BACKEND": "channels.layers.InMemoryChannelLayer"},
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

# Certificate validity defaults; can be tightened via env vars.
KEYWARDEN_AGENT_CERT_VALIDITY_DAYS = int(os.getenv("KEYWARDEN_AGENT_CERT_VALIDITY_DAYS", "90"))
KEYWARDEN_USER_CERT_VALIDITY_DAYS = int(os.getenv("KEYWARDEN_USER_CERT_VALIDITY_DAYS", "30"))
KEYWARDEN_SHELL_CERT_VALIDITY_MINUTES = int(os.getenv("KEYWARDEN_SHELL_CERT_VALIDITY_MINUTES", "15"))
KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE = os.getenv(
    "KEYWARDEN_ACCOUNT_USERNAME_TEMPLATE", "{{username}}_{{user_id}}"
)
KEYWARDEN_HEARTBEAT_STALE_SECONDS = int(os.getenv("KEYWARDEN_HEARTBEAT_STALE_SECONDS", "120"))

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
    # Force a consistent admin theme; disables theme switching.
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
OIDC_OP_DISCOVERY_ENDPOINT = os.getenv("KEYWARDEN_OIDC_DISCOVERY_ENDPOINT")
OIDC_OP_AUTHORIZATION_ENDPOINT = os.getenv("KEYWARDEN_OIDC_AUTHORIZATION_ENDPOINT")
OIDC_OP_TOKEN_ENDPOINT = os.getenv("KEYWARDEN_OIDC_TOKEN_ENDPOINT")
OIDC_OP_USER_ENDPOINT = os.getenv("KEYWARDEN_OIDC_USER_ENDPOINT")
OIDC_OP_JWKS_ENDPOINT = os.getenv("KEYWARDEN_OIDC_JWKS_ENDPOINT")
OIDC_RP_SIGN_ALGO = os.getenv("KEYWARDEN_OIDC_SIGN_ALGO", "RS256")
OIDC_RP_SCOPES = os.getenv("KEYWARDEN_OIDC_SCOPES", "openid email profile")
OIDC_STORE_ACCESS_TOKEN = env_bool("KEYWARDEN_OIDC_STORE_ACCESS_TOKEN", default=False)
OIDC_CREATE_USER = True

KEYWARDEN_OIDC_PROVIDER_ID = os.getenv("KEYWARDEN_OIDC_PROVIDER_ID", "oidc")
KEYWARDEN_OIDC_ISSUER = os.getenv("KEYWARDEN_OIDC_ISSUER", "").strip()
KEYWARDEN_OIDC_EMAIL_CLAIM = os.getenv("KEYWARDEN_OIDC_EMAIL_CLAIM", "email")
KEYWARDEN_OIDC_EMAIL_VERIFIED_CLAIM = os.getenv("KEYWARDEN_OIDC_EMAIL_VERIFIED_CLAIM", "email_verified")
KEYWARDEN_OIDC_REQUIRE_VERIFIED_EMAIL = env_bool("KEYWARDEN_OIDC_REQUIRE_VERIFIED_EMAIL", default=True)
KEYWARDEN_OIDC_USERNAME_CLAIM = os.getenv("KEYWARDEN_OIDC_USERNAME_CLAIM", "preferred_username")
KEYWARDEN_OIDC_GROUPS_CLAIM = os.getenv("KEYWARDEN_OIDC_GROUPS_CLAIM", "groups")
KEYWARDEN_OIDC_SYNC_ADMIN_FROM_GROUPS = env_bool("KEYWARDEN_OIDC_SYNC_ADMIN_FROM_GROUPS", default=False)
KEYWARDEN_OIDC_ADMIN_DEMOTE_ON_MISS = env_bool("KEYWARDEN_OIDC_ADMIN_DEMOTE_ON_MISS", default=False)
KEYWARDEN_OIDC_ADMIN_GROUPS = env_csv("KEYWARDEN_OIDC_ADMIN_GROUPS")

KEYWARDEN_OIDC_ENABLED = bool(
    OIDC_RP_CLIENT_ID
    and OIDC_RP_CLIENT_SECRET
    and (
        OIDC_OP_DISCOVERY_ENDPOINT
        or (
            OIDC_OP_AUTHORIZATION_ENDPOINT
            and OIDC_OP_TOKEN_ENDPOINT
            and OIDC_OP_USER_ENDPOINT
            and OIDC_OP_JWKS_ENDPOINT
        )
    )
)

KEYWARDEN_SOCIAL_LOGIN_PROVIDERS = []
if KEYWARDEN_SOCIAL_GOOGLE_CONFIGURED:
    KEYWARDEN_SOCIAL_LOGIN_PROVIDERS.append(
        {"id": "google", "name": "Google", "login_url": "/accounts/sso/google/login/"}
    )
if KEYWARDEN_SOCIAL_GITHUB_CONFIGURED:
    KEYWARDEN_SOCIAL_LOGIN_PROVIDERS.append(
        {"id": "github", "name": "GitHub", "login_url": "/accounts/sso/github/login/"}
    )
if KEYWARDEN_SOCIAL_APPLE_CONFIGURED:
    KEYWARDEN_SOCIAL_LOGIN_PROVIDERS.append(
        {"id": "apple", "name": "Apple", "login_url": "/accounts/sso/apple/login/"}
    )

if KEYWARDEN_SOCIAL_AUTH_ENABLED:
    SITE_ID = int(os.getenv("KEYWARDEN_SITE_ID", "1"))
    ACCOUNT_EMAIL_REQUIRED = True
    ACCOUNT_UNIQUE_EMAIL = True
    ACCOUNT_USERNAME_REQUIRED = False
    ACCOUNT_AUTHENTICATION_METHOD = "email"
    SOCIALACCOUNT_AUTO_SIGNUP = True
    SOCIALACCOUNT_EMAIL_AUTHENTICATION = False
    SOCIALACCOUNT_ADAPTER = "apps.accounts.social_auth.KeywardenSocialAccountAdapter"
    SOCIALACCOUNT_LOGIN_ON_GET = True
    SOCIALACCOUNT_PROVIDERS = {}

    if KEYWARDEN_SOCIAL_GOOGLE_CONFIGURED:
        SOCIALACCOUNT_PROVIDERS["google"] = {
            "SCOPE": ["profile", "email"],
            "APPS": [
                {
                    "client_id": KEYWARDEN_SOCIAL_GOOGLE_CLIENT_ID,
                    "secret": KEYWARDEN_SOCIAL_GOOGLE_CLIENT_SECRET,
                    "key": "",
                }
            ],
        }

    if KEYWARDEN_SOCIAL_GITHUB_CONFIGURED:
        SOCIALACCOUNT_PROVIDERS["github"] = {
            "SCOPE": ["read:user", "user:email"],
            "APPS": [
                {
                    "client_id": KEYWARDEN_SOCIAL_GITHUB_CLIENT_ID,
                    "secret": KEYWARDEN_SOCIAL_GITHUB_CLIENT_SECRET,
                    "key": "",
                }
            ],
        }

    if KEYWARDEN_SOCIAL_APPLE_CONFIGURED:
        SOCIALACCOUNT_PROVIDERS["apple"] = {
            "SCOPE": ["name", "email"],
            "APPS": [
                {
                    "client_id": KEYWARDEN_SOCIAL_APPLE_CLIENT_ID,
                    "secret": KEYWARDEN_SOCIAL_APPLE_CLIENT_SECRET,
                    "key": "",
                }
            ],
        }

KEYWARDEN_SOCIAL_REQUIRE_VERIFIED_EMAIL = env_bool(
    "KEYWARDEN_SOCIAL_REQUIRE_VERIFIED_EMAIL",
    default=True,
)

# Auth mode: native | oidc | hybrid
AUTH_MODE = os.getenv("KEYWARDEN_AUTH_MODE", "hybrid").lower()
if AUTH_MODE not in {"native", "oidc", "hybrid"}:
    AUTH_MODE = "hybrid"
if AUTH_MODE == "oidc" and not KEYWARDEN_OIDC_ENABLED:
    AUTH_MODE = "native"
KEYWARDEN_AUTH_MODE = AUTH_MODE

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "guardian.backends.ObjectPermissionBackend",
]
if KEYWARDEN_SOCIAL_AUTH_ENABLED:
    AUTHENTICATION_BACKENDS.append("allauth.account.auth_backends.AuthenticationBackend")
if KEYWARDEN_OIDC_ENABLED:
    AUTHENTICATION_BACKENDS.append("apps.accounts.oidc.KeywardenOIDCAuthenticationBackend")

if AUTH_MODE == "oidc":
    # OIDC-only: enforce identity provider logins.
    LOGIN_URL = "/oidc/authenticate/"
else:
    LOGIN_URL = "/accounts/login/"
LOGOUT_URL = "/oidc/logout/" if KEYWARDEN_OIDC_ENABLED else "/accounts/logout/"
LOGIN_REDIRECT_URL = "/servers/"
LOGOUT_REDIRECT_URL = "/"

ANONYMOUS_USER_NAME = None

def permission_callback(request):
    # Guard admin-side model changes behind a single permission check.
    return request.user.has_perm("keywarden.change_model")

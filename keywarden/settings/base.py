import os
from pathlib import Path
from dotenv import load_dotenv

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
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "apps.accounts",
    "apps.core",
    "apps.dashboard",
    "ninja",                # Django Ninja API
    "unfold",               # Admin UI
    "unfold.contrib.filters",
    "mozilla_django_oidc",   # OIDC Client
    "tailwind",
    "theme"
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "whitenoise.middleware.WhiteNoiseMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
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

CACHES = {
    "default": {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": "redis://keywarden-valkey:6379/1",
        "OPTIONS": {"CLIENT_CLASS": "django_redis.client.DefaultClient"},
    }
}

SESSION_ENGINE = "django.contrib.sessions.backends.cache"
SESSION_CACHE_ALIAS = "default"

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
        ]},
    },
]

AUTHENTICATION_BACKENDS = [
    "mozilla_django_oidc.auth.OIDCAuthenticationBackend",  # OIDC authentication
    "django.contrib.auth.backends.ModelBackend",           # default Django auth
]

UNFOLD = {
    "SITE_TITLE": "Keywarden Admin",
    "SITE_HEADER": "Keywarden",
    "SHOW_HISTORY": True,
    "SITE_URL": "/",
    "LOGIN_REDIRECT_URL": "/admin/",
    "ENVIRONMENT": "Keywarden",
    "ENVIRONMENT_COLOR": "#7C3AED",
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
    ],
    "SCRIPTS": [
        "/static/unfold/js/simplebar.js",
        "/static/unfold/js/alpine.js",
    ],
}

OIDC_RP_CLIENT_ID = os.getenv("KEYWARDEN_OIDC_CLIENT_ID")
OIDC_RP_CLIENT_SECRET = os.getenv("KEYWARDEN_OIDC_CLIENT_SECRET")
OIDC_OP_AUTHORIZATION_ENDPOINT = os.getenv("KEYWARDEN_OIDC_AUTHORIZATION_ENDPOINT")
OIDC_OP_TOKEN_ENDPOINT = os.getenv("KEYWARDEN_OIDC_TOKEN_ENDPOINT")
OIDC_OP_USER_ENDPOINT = os.getenv("KEYWARDEN_OIDC_USER_ENDPOINT")
OIDC_OP_JWKS_ENDPOINT = os.getenv("KEYWARDEN_OIDC_JWKS_ENDPOINT")

LOGIN_URL = "/oidc/authenticate/"
LOGOUT_URL = "/oidc/logout/"
LOGIN_REDIRECT_URL = "/"
LOGOUT_REDIRECT_URL = "/"
# prod.py
from .base import *  # noqa: F403

DEBUG = False
SECURE_SSL_REDIRECT = True
CSRF_COOKIE_SECURE = True
SESSION_COOKIE_SECURE = True
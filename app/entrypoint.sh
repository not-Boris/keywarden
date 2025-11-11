#!/bin/sh
set -eu

# Build Tailwind CSS (best-effort; skip if not configured)
python manage.py tailwind install || true
python manage.py tailwind build || true

# Collect static files so Tailwind CSS is served
python manage.py collectstatic --noinput

python manage.py migrate --noinput
python manage.py ensure_admin

exec gunicorn keywarden.wsgi:application --bind 0.0.0.0:80 --workers 3



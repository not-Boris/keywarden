#!/bin/sh
set -eu

python manage.py migrate --noinput
python manage.py ensure_admin

exec gunicorn keywarden.wsgi:application --bind 0.0.0.0:80 --workers 3



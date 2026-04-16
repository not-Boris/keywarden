#!/bin/sh
set -eu

exec gunicorn keywarden.wsgi:application \
    --bind 0.0.0.0:8000 \
    --workers 3 \
    --access-logfile /var/log/keywarden/gunicorn-access.log \
    --error-logfile /var/log/keywarden/gunicorn-error.log \
    --capture-output \
    --log-level info

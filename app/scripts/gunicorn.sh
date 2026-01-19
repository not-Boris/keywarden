#!/bin/sh
set -eu

exec gunicorn keywarden.wsgi:application --bind 0.0.0.0:8000 --workers 3

#!/bin/sh
set -eu

exec daphne -b 0.0.0.0 -p 8001 keywarden.asgi:application

#!/bin/sh
set -eu

DOMAIN="${KEYWARDEN_DOMAIN:-localhost}"
CERT_DIR="/etc/nginx/certs"
NGINX_TEMPLATE="/etc/nginx/nginx.conf.template"
NGINX_CONF="/etc/nginx/nginx.conf"

# Replaces server_name in nginx.conf with $KEYWARDEN_DOMAIN
if [ -f "$NGINX_TEMPLATE" ]; then
    ESCAPED_DOMAIN=$(printf '%s' "$DOMAIN" | sed 's/[&/]/\\&/g')
    sed "s/__SERVER_NAME__/${ESCAPED_DOMAIN}/g" "$NGINX_TEMPLATE" > "$NGINX_CONF"
fi

# Creates self-signed certs using mkcert $KEYWARDEN_DOMAIN, and renaming them.
if [ ! -f "$CERT_DIR/certificate.pem" ] || [ ! -f "$CERT_DIR/key.pem" ]; then
    mkdir -p "$CERT_DIR"
    if command -v mkcert >/dev/null 2>&1; then
        mkcert -install >/dev/null 2>&1 || true
        mkcert -cert-file "$CERT_DIR/certificate.pem" -key-file "$CERT_DIR/key.pem" "$DOMAIN"
    else
        openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
            -subj "/CN=$DOMAIN" \
            -keyout "$CERT_DIR/key.pem" \
            -out "$CERT_DIR/certificate.pem"
    fi
fi

# Build Tailwind CSS (best-effort; skip if not configured)
python manage.py tailwind install || true
python manage.py tailwind build || true

# Collect static files so Tailwind CSS is served
python manage.py collectstatic --noinput

python manage.py migrate --noinput
python manage.py ensure_admin

# Ensure application log directory exists and is writable by the Django runtime user.
mkdir -p /var/log/keywarden
chown -R djangouser:djangouser /var/log/keywarden || true

exec /usr/bin/supervisord -c /etc/supervisor/supervisord.conf

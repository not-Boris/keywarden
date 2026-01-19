# =============================================
# 1. Base image — Python with system dependencies
# =============================================
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=off \
    PIP_DISABLE_PIP_VERSION_CHECK=on

WORKDIR /app

# System deps for psycopg2, node (for Tailwind), etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    curl \
    nginx \
    nodejs \
    npm \
    supervisor \
    && rm -rf /var/lib/apt/lists/*

# =============================================
# 2. Install Python dependencies
# =============================================

COPY requirements.txt .

RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# =============================================
# 3. Build Tailwind assets
# =============================================
# If you’re using django-tailwind or npm-based Tailwind build
#COPY ./frontend ./frontend
#WORKDIR /app/frontend
#RUN npm install && npm run build

# =============================================
# 4. Collect static assets
# =============================================
WORKDIR /app
COPY ./app .

COPY nginx/configs/nginx.conf /etc/nginx/nginx.conf
COPY nginx/configs/options-* /etc/nginx/
#COPY nginx/configs/sites/ /etc/nginx/conf.d/
COPY supervisor/supervisord.conf /etc/supervisor/supervisord.conf

RUN python manage.py collectstatic --noinput
RUN chmod +x /app/entrypoint.sh /app/scripts/gunicorn.sh

# =============================================
# 5. Create users for services
# =============================================
RUN adduser --system --no-create-home --group nginx \
    && adduser --disabled-password --gecos '' djangouser

RUN mkdir -p /var/cache/nginx \
    && chown -R nginx:nginx /var/cache/nginx

EXPOSE 443 8008

# =============================================
# 6. Launch the app
# =============================================
CMD ["./entrypoint.sh"]

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
    nodejs \
    npm \
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

RUN python manage.py collectstatic --noinput

# =============================================
# 5. Create non-root user
# =============================================
RUN adduser --disabled-password --gecos '' djangouser
USER djangouser

EXPOSE 80

# =============================================
# 6. Launch the app
# =============================================
CMD ["gunicorn", "keywarden.wsgi:application", "--bind", "0.0.0.0:8000", "--workers", "3"]
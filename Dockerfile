# syntax=docker/dockerfile:1

############################
# Builder (compile wheels) #
############################
FROM python:3.11-slim AS builder
ENV PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential gcc libffi-dev libssl-dev libpq-dev pkg-config cargo \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels
COPY requirements.txt ./
RUN python -m pip install --upgrade pip setuptools wheel
# Build/download wheels for all deps
RUN pip wheel --wheel-dir /wheels -r requirements.txt

#######################
# Runtime (slim)      #
#######################

FROM python:3.11-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY --from=builder /wheels /wheels
COPY requirements.txt ./
# Tell pip to ONLY use wheels from /wheels for the exact versions you built
RUN python -m pip install --no-index --find-links=/wheels -r requirements.txt

COPY . .
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
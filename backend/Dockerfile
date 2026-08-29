# Multi-stage production Dockerfile for TRUSTINEL Backend
FROM ghcr.io/astral-sh/uv:python3.12-alpine AS builder

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1

COPY pyproject.toml /app/

RUN --mount=type=cache,target=/root/.cache/uv \
    uv pip install --system -r pyproject.toml

# Final runtime image
FROM python:3.12-alpine

# Install wget for healthcheck probe
RUN apk add --no-cache wget

WORKDIR /app

# Create non-root system user for security hardening
RUN adduser -D -u 10001 trustinel

# Copy system dependencies from builder
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy app code, database migrations, configuration, and entrypoint
COPY app/ /app/app/
COPY alembic/ /app/alembic/
COPY alembic.ini /app/alembic.ini
COPY entrypoint.sh /app/entrypoint.sh

RUN chmod +x /app/entrypoint.sh && chown -R trustinel:trustinel /app

# Ensure log output is unbuffered
ENV PYTHONUNBUFFERED=1

# Container native healthcheck (sends GET request to /health)
HEALTHCHECK --interval=10s --timeout=5s --start-period=5s --retries=3 \
  CMD wget -q -O - http://localhost:8000/health | grep -q '"status"' || exit 1

USER trustinel

EXPOSE 8000

ENTRYPOINT ["/app/entrypoint.sh"]
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

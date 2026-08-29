#!/bin/sh
set -e

echo "[TRUSTINEL] Running database migrations..."
alembic upgrade head || { echo "[TRUSTINEL] Database migration failed!"; exit 1; }
echo "[TRUSTINEL] Database migrations completed successfully."

exec "$@"

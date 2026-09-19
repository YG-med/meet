#!/usr/bin/env bash
set -euo pipefail

echo "[1/2] Initializing database and storage..."
python init_db.py

echo "[2/2] Starting Gunicorn on port ${PORT:-10000}..."
exec gunicorn app:app --bind 0.0.0.0:${PORT:-10000} --workers 2 --threads 4 --timeout 120 --access-logfile - --error-logfile -

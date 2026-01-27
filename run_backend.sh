#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/clawd/autore
source .venv/bin/activate
exec uvicorn backend.app:app --host 0.0.0.0 --port 5555

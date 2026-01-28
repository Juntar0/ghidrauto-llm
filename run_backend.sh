#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source .venv/bin/activate
# Ensure user-local binaries (e.g., capa) are on PATH
export PATH="$HOME/.local/bin:$PATH"
# Multiple workers prevent UI fetches (disasm/ghidra/summary) from queueing behind slow endpoints.
# You can override via: UVICORN_WORKERS=1 ./run_backend.sh
UVICORN_WORKERS="${UVICORN_WORKERS:-4}"
exec uvicorn backend.app:app --host 0.0.0.0 --port 5555 --workers "$UVICORN_WORKERS"

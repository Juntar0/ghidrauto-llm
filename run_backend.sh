#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source .venv/bin/activate
# Ensure user-local binaries (e.g., capa) are on PATH
export PATH="$HOME/.local/bin:$PATH"
exec uvicorn backend.app:app --host 0.0.0.0 --port 5555

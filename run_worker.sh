#!/usr/bin/env bash
set -euo pipefail
cd /home/ubuntu/clawd/autore
source .venv/bin/activate
exec python -m worker.run

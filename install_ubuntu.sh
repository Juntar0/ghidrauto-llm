#!/usr/bin/env bash
set -euo pipefail

# Fresh-host installer for AutoRE on Ubuntu.
# - Installs OS deps (Python venv, Java)
# - Downloads & extracts Ghidra (analyzeHeadless)
# - Creates Python venv and installs requirements
# - Creates .env from .env.example (no secrets)
#
# Assumptions:
# - You run this on Ubuntu 22.04/24.04 (or compatible).
# - You have sudo.

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_DIR"

GHIDRA_VERSION_DEFAULT="12.0.1"
GHIDRA_VERSION="${GHIDRA_VERSION:-$GHIDRA_VERSION_DEFAULT}"

# Choose a known-good OpenJDK
JAVA_PKG="openjdk-17-jre-headless"

need_cmd() {
  command -v "$1" >/dev/null 2>&1
}

echo "[1/5] Installing OS packages..."
if ! need_cmd sudo; then
  echo "sudo is required" >&2
  exit 1
fi

sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  ca-certificates curl wget unzip git \
  python3 python3-venv python3-pip \
  "$JAVA_PKG"

echo "[2/5] Installing Ghidra ${GHIDRA_VERSION}..."
mkdir -p "$REPO_DIR/.deps"
cd "$REPO_DIR/.deps"

# Download from GitHub releases (NSA/ghidra). You can override by setting:
#   GHIDRA_ZIP_URL=https://.../ghidra_<ver>_PUBLIC_<date>.zip
# or by placing the zip into $REPO_DIR/.deps

FOUND_ZIP=""
if ls ghidra_*_PUBLIC_*.zip >/dev/null 2>&1; then
  FOUND_ZIP="$(ls -1 ghidra_*_PUBLIC_*.zip | head -n1)"
fi

if [[ -z "$FOUND_ZIP" ]]; then
  if [[ -n "${GHIDRA_ZIP_URL:-}" ]]; then
    echo "Downloading Ghidra from GHIDRA_ZIP_URL..."
    FOUND_ZIP="ghidra_${GHIDRA_VERSION}_PUBLIC.zip"
    curl -L --fail -o "$FOUND_ZIP" "$GHIDRA_ZIP_URL"
  else
    echo "Resolving Ghidra ${GHIDRA_VERSION} release asset from GitHub API..."
    # Use GitHub API to find a release asset that matches ghidra_<ver>_PUBLIC_*.zip
    ASSET_URL="$(
      python3 - <<'PY'
import json, sys, urllib.request
ver = sys.argv[1]
api = 'https://api.github.com/repos/NationalSecurityAgency/ghidra/releases'
req = urllib.request.Request(api, headers={'User-Agent':'autore-installer'})
with urllib.request.urlopen(req, timeout=60) as r:
    data = json.load(r)
pat = f"ghidra_{ver}_PUBLIC_"
for rel in data:
    for a in (rel.get('assets') or []):
        name = a.get('name') or ''
        if name.startswith(pat) and name.endswith('.zip'):
            print(a.get('browser_download_url') or '')
            raise SystemExit(0)
print('')
PY
      "$GHIDRA_VERSION"
    )"
    if [[ -z "$ASSET_URL" ]]; then
      echo "ERROR: Could not auto-resolve Ghidra ${GHIDRA_VERSION} zip from GitHub API." >&2
      echo "Either set GHIDRA_ZIP_URL or manually download the zip into: $REPO_DIR/.deps" >&2
      exit 2
    fi
    FOUND_ZIP="$(basename "$ASSET_URL")"
    echo "Downloading: $ASSET_URL"
    curl -L --fail -o "$FOUND_ZIP" "$ASSET_URL"
  fi
fi

# Extract
rm -rf ghidra
mkdir -p ghidra
unzip -q "$FOUND_ZIP" -d ghidra

GHIDRA_DIR="$(find ghidra -maxdepth 2 -type d -name 'ghidra_*_PUBLIC' | head -n1)"
if [[ -z "$GHIDRA_DIR" ]]; then
  echo "Failed to locate extracted Ghidra directory" >&2
  exit 3
fi

ANALYZE_HEADLESS="$REPO_DIR/.deps/$GHIDRA_DIR/support/analyzeHeadless"
if [[ ! -x "$ANALYZE_HEADLESS" ]]; then
  echo "analyzeHeadless not found at: $ANALYZE_HEADLESS" >&2
  exit 4
fi

cd "$REPO_DIR"

echo "[3/5] Creating venv + installing Python dependencies..."
if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade pip wheel >/dev/null
python -m pip install -r requirements.txt

echo "[4/5] Creating .env (no secrets)..."
if [[ ! -f .env ]]; then
  cp .env.example .env
fi

# Patch safe path settings to this repo
patch_kv() {
  local key="$1"
  local val="$2"
  if grep -qE "^${key}=" .env; then
    perl -0777 -i -pe "s/^${key}=.*\$/${key}=${val}/m" .env
  else
    printf '\n%s=%s\n' "$key" "$val" >> .env
  fi
}

patch_kv "AUTORE_WORK_DIR" "$REPO_DIR/work"
patch_kv "GHIDRA_SCRIPTS_DIR" "$REPO_DIR/ghidra_scripts"
patch_kv "GHIDRA_ANALYZE_HEADLESS" "$ANALYZE_HEADLESS"

mkdir -p work logs

echo "[5/5] Done."
cat <<EOF

Next steps:
1) Edit $REPO_DIR/.env and set AI config (choose at least one):
   - ANTHROPIC_API_KEY
   - OPENAI_BASE_URL (+ optional OPENAI_API_KEY)
2) Start services:
   ./run_backend.sh
   ./run_worker.sh
3) Open: http://<host>:5555/

NOTE: This script does not install Node/npm (not needed for production assets).
EOF

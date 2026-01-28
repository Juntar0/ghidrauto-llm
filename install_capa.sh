#!/usr/bin/env bash
set -euo pipefail

# Install FLARE CAPA standalone binary.
# Default: install into ~/.local/bin (no sudo).
# If sudo is available and /usr/local/bin is writable, installs there.

CAPA_VERSION_DEFAULT="7.4.0"
CAPA_VERSION="${CAPA_VERSION:-$CAPA_VERSION_DEFAULT}"

ZIP_NAME="capa-v${CAPA_VERSION}-linux.zip"
URL_DEFAULT="https://github.com/mandiant/capa/releases/download/v${CAPA_VERSION}/${ZIP_NAME}"
CAPA_ZIP_URL="${CAPA_ZIP_URL:-$URL_DEFAULT}"

say() { echo "[capa-install] $*"; }

TARGET_DIR_USER="$HOME/.local/bin"
TARGET_DIR_SYSTEM="/usr/local/bin"

# If already installed, exit 0
if command -v capa >/dev/null 2>&1; then
  say "capa already installed: $(command -v capa)"
  capa --version || true
  exit 0
fi

WORK_DIR="${TMPDIR:-/tmp}/capa-install.$$"
mkdir -p "$WORK_DIR"
trap 'rm -rf "$WORK_DIR"' EXIT

say "Downloading ${CAPA_ZIP_URL}"
cd "$WORK_DIR"

if command -v curl >/dev/null 2>&1; then
  curl -L --fail -o "$ZIP_NAME" "$CAPA_ZIP_URL"
elif command -v wget >/dev/null 2>&1; then
  wget -O "$ZIP_NAME" "$CAPA_ZIP_URL"
else
  say "ERROR: curl or wget required" >&2
  exit 2
fi

say "Extracting"
unzip -q "$ZIP_NAME"

if [[ ! -f capa ]]; then
  say "ERROR: extracted zip did not contain 'capa' binary" >&2
  ls -la
  exit 3
fi
chmod +x capa

# Choose install target
INSTALL_DIR="$TARGET_DIR_USER"
if [[ -w "$TARGET_DIR_SYSTEM" ]]; then
  INSTALL_DIR="$TARGET_DIR_SYSTEM"
elif command -v sudo >/dev/null 2>&1; then
  # If sudo works, prefer /usr/local/bin
  if sudo -n true >/dev/null 2>&1; then
    INSTALL_DIR="$TARGET_DIR_SYSTEM"
  fi
fi

say "Installing to ${INSTALL_DIR}"
if [[ "$INSTALL_DIR" == "$TARGET_DIR_SYSTEM" ]]; then
  if [[ -w "$TARGET_DIR_SYSTEM" ]]; then
    mv capa "$TARGET_DIR_SYSTEM/capa"
  else
    sudo mv capa "$TARGET_DIR_SYSTEM/capa"
    sudo chmod +x "$TARGET_DIR_SYSTEM/capa"
  fi
else
  mkdir -p "$TARGET_DIR_USER"
  mv capa "$TARGET_DIR_USER/capa"
  chmod +x "$TARGET_DIR_USER/capa"
fi

# Verify
if ! command -v capa >/dev/null 2>&1; then
  # If installed to ~/.local/bin but PATH doesn't include it
  if [[ -x "$TARGET_DIR_USER/capa" ]]; then
    say "Installed to $TARGET_DIR_USER/capa but not on PATH. Add to PATH: export PATH=\"$TARGET_DIR_USER:$PATH\""
  fi
  say "ERROR: capa not found on PATH after install" >&2
  exit 4
fi

say "OK: $(command -v capa)"
capa --version || true

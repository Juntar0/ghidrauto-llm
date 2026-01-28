# CHANGELOG - 2026-01-28 (Installer / Ops)

## Ubuntu installer
- `install_ubuntu.sh` は OpenJDK 21 (headless) をインストールする構成
  - `openjdk-21-jdk-headless`
  - Ghidra 12.x の要件を満たす

## CAPA installer
- `install_capa.sh` を追加
  - ~/.local/bin への導入（sudo不要）を優先
  - 可能なら /usr/local/bin へ導入
- `run_backend.sh` / `run_worker.sh` で ~/.local/bin を PATH に追加

---

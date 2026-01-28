# CHANGELOG - 2026-01-28 (Backend / Worker)

## Worker
- summarize 系タスクで worker が `UnboundLocalError` で落ちる問題を修正（is_summary_task 初期化順）

## Chat tools
- `backend/chat_tools_v2.py` が実際のディレクトリ構造（extract/analysis.json, ai/results, ai/index.json）と不一致で機能していなかった問題を修正
- `get_callgraph` を calls_out/called_by ベースで実装
- CAPA artifacts 取得をサポート

## CAPA
- `install_capa.sh` を追加し、UI から未導入時に自動導入を試行できるように変更
- Backend エンドポイント追加: `GET /api/tools/capa/status`, `POST /api/tools/capa/install`

---

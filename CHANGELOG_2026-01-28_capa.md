# CHANGELOG - 2026-01-28 (CAPA Integration)

## 追加機能：CAPA統合（マルウェア能力検出）

## 追記（2026-01-28 後半）: CAPA インストーラー + UI自動導入
- `install_capa.sh` を追加（standalone capa を ~/.local/bin もしくは /usr/local/bin に導入）
- `run_backend.sh` / `run_worker.sh` が `~/.local/bin` を PATH に追加（ユーザー導入でも検出可能）
- Backend: `GET /api/tools/capa/status`, `POST /api/tools/capa/install` を追加
- Frontend: **CAPA** ボタン押下時に未導入なら自動導入を試行し、導入後は Re-extract を促す

### 概要
FLARE CAPAをExtract時に自動実行し、検出されたマルウェア能力をUI表示する機能を実装。

### 変更内容

#### 1. Backend（extractor.py）

**新規関数: `run_capa_analysis()`**
- Extract時に自動実行（Ghidra解析の後）
- CAPA未インストール時は非致命的エラー（extract結果は正常に返す）
- 出力: `extract/capa.json`
- タイムアウト: 300秒（デフォルト）

**エラーハンドリング**:
- CAPA未インストール → `{"error": "capa not installed", "installed": false}`
- CAPA失敗 → `{"error": "capa failed with exit code X"}`
- タイムアウト → `{"error": "capa timeout", "timeout": 300}`

**実行コマンド**:
```bash
capa <sample_path> --json <capa.json>
```

#### 2. Backend（app.py）

**Extract処理に統合**:
- `run_ghidra_extract()` の直後に `run_capa_analysis()` を実行
- CAPA失敗は非致命的（Ghidra結果は有効）

**新規APIエンドポイント**:
```
GET /api/jobs/{job_id}/capa
```
- 返却: `capa.json`の内容
- 404: CAPA結果が存在しない場合

#### 3. Frontend（App.tsx）

**新規タブ: CAPA**
- モバイルタブボタン追加（Disasm/Ghidra/AI/CAPA）
- デスクトップでは4カラム目として表示

**表示内容**:
- **ヘッダー**: 検出能力数 + バイナリメタ情報（format/arch/os）
- **能力リスト**: 折りたたみ可能な詳細表示
  - ルール名 + namespace
  - Matches（最大10件表示、それ以上は "... and N more"）
  - ATT&CK Tactics/Techniques

**データ読み込み**:
- `loadJob()` で `loadCapa(id)` を自動実行（非ブロッキング）
- エラー時は「CAPA not available」表示
- インストールガイド表示（未インストール時）

**UI構造**:
```tsx
<section className='pane' style={...}>
  <div className='paneHeader'>
    <h4>CAPA</h4>
    <span className='sub'>Malware Capability Detection</span>
  </div>
  <div className='paneBody'>
    {/* Capabilities list */}
  </div>
</section>
```

### CAPA出力例

```json
{
  "meta": {
    "analysis": {
      "format": "PE",
      "arch": "x86",
      "os": "windows"
    },
    "rules": {
      "rule_count": 800
    }
  },
  "rules": {
    "create file": {
      "namespace": "host-interaction/file-system/create",
      "matches": [
        {
          "address": "0x401234",
          "description": "CreateFileA API call"
        }
      ],
      "attack": [
        {"id": "T1027", "tactic": "Defense Evasion"}
      ]
    }
  }
}
```

### インストール要件

**CAPA本体**（サーバー側）:
```bash
wget https://github.com/mandiant/capa/releases/download/v7.0.1/capa-v7.0.1-linux.zip
unzip capa-v7.0.1-linux.zip
sudo mv capa /usr/local/bin/
sudo chmod +x /usr/local/bin/capa
```

**依存関係**: なし（standalone binary）

### テスト方法
```bash
cd ~/ghidrauto-llm
git pull origin main

# 既存ジョブで再extract（CAPA自動実行）
curl -X POST http://localhost:8000/api/jobs/<job_id>/reextract

# または新規アップロード
```

UIで「CAPA」タブを開き、検出された能力を確認。

### 制限事項
- CAPA未インストール時はスキップ（非致命的）
- サポート形式: PE/ELF/MachO（CAPA自体の制限）
- 大きなバイナリは300秒でタイムアウト

### 将来の拡張
- 関数単位でのCAPAマッチ表示
- ATT&CK tacticsでフィルタリング
- カスタムルール追加サポート

# CAPA インストール手順

CAPAは、FLARE CAPAマルウェア能力検出ツールです。ghidrauto-llmのExtract処理で自動実行されます。

## インストール（Ubuntu/Debian）

### 推奨: 付属インストーラー（自動）
`ghidrauto-llm` には CAPA の簡易インストーラーを同梱しています。

```bash
cd ~/ghidrauto-llm
chmod +x install_capa.sh
./install_capa.sh
```

> UI の **CAPA** ボタン押下時も、未インストールなら自動でインストーラー実行を試みます。

### 手動: 1. CAPAバイナリのダウンロード

```bash
cd /tmp
wget https://github.com/mandiant/capa/releases/download/v7.4.0/capa-v7.4.0-linux.zip
```

### 2. 解凍とインストール

```bash
unzip capa-v7.4.0-linux.zip
sudo mv capa /usr/local/bin/
sudo chmod +x /usr/local/bin/capa
```

### 3. 確認

```bash
capa --version
# 出力: capa 7.4.0
```

## 動作確認

### 基本的な使い方

```bash
# 標準出力（テーブル形式）
capa /path/to/sample.exe

# JSON出力（ghidrauto-llmが使用）
capa /path/to/sample.exe -j > output.json
```

### テストサンプルで確認

```bash
# テスト用バイナリで試す
capa /home/ubuntu/clawd/autore/.venv/lib/python3.12/site-packages/pip/_vendor/distlib/t32.exe

# JSON出力をファイルに保存
capa /path/to/sample.exe -j > /tmp/test_capa.json

# JSON出力を確認（jqがある場合）
cat /tmp/test_capa.json | jq '.rules | keys'
```

## ghidrauto-llm との統合

CAPAは **自動的に実行されます**：
- バイナリアップロード → Extract → CAPA自動実行
- 結果: `work/<job_id>/extract/capa.json`
- UI: **CAPA** タブで表示

## トラブルシューティング

### CAPAが見つからない

```bash
which capa
# 出力なし → インストールされていない
```

解決策：上記のインストール手順を実行してください。

### DeprecationWarning が表示される

```
main.py:1109: DeprecationWarning: This is the last capa version supporting Python 3.8 and 3.9.
```

**これは正常です**。CAPA v7.4.0の既知の警告です。機能には影響ありません。

### JSON出力に警告が混入する

CAPA実行時は stderr をリダイレクトして警告を除外します：

```bash
capa sample.exe -j 2>/dev/null > output.json
```

ghidrauto-llmでは自動的に処理されます（log ファイルに分離）。

### 対応フォーマット

- PE (Windows)
- ELF (Linux)
- MachO (macOS)
- shellcode (sc32/sc64)

非対応フォーマットの場合は、`capa.json` にエラーメッセージが記録されます（Extract処理は正常に継続）。

## アップグレード

新バージョンへの更新：

```bash
cd /tmp
wget https://github.com/mandiant/capa/releases/download/vX.Y.Z/capa-vX.Y.Z-linux.zip
unzip capa-vX.Y.Z-linux.zip
sudo mv capa /usr/local/bin/
sudo chmod +x /usr/local/bin/capa
```

最新リリース: https://github.com/mandiant/capa/releases

## 依存関係

- **なし** - standalone binary（依存パッケージ不要）
- Python不要
- Rules: 初回実行時に自動ダウンロード

## ライセンス

CAPA: Apache 2.0 License  
https://github.com/mandiant/capa

## 参考リンク

- 公式リポジトリ: https://github.com/mandiant/capa
- ドキュメント: https://github.com/mandiant/capa/tree/master/doc
- ルール: https://github.com/mandiant/capa-rules

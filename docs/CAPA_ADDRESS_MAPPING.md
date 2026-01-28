# CAPA と Ghidra のアドレスマッピング

## 問題

CAPAで検出された関数のアドレスと、Ghidraで解析された関数のアドレスが一致するかどうかを確認する必要があります。

## アドレスの種類

### 仮想アドレス（VA: Virtual Address）
- プログラムがメモリにロードされたときの絶対アドレス
- 例: `0x401000`
- **Image Base + RVA** で計算される

### 相対仮想アドレス（RVA: Relative Virtual Address）
- Image Baseからの相対オフセット
- 例: `0x1000`
- **VA - Image Base** で計算される

## CAPAのアドレス形式

CAPAの出力（`capa.json`）を確認：
```json
{
  "meta": {
    "analysis": {
      "base_address": {"type": "absolute", "value": 4194304}  // 0x400000
    }
  },
  "rules": {
    "some rule": {
      "matches": [
        [{"type": "absolute", "value": 4198400}]  // 0x401000
      ]
    }
  }
}
```

**結論**: CAPAは **仮想アドレス（VA）** を使用

## Ghidraのアドレス形式

ExtractAnalysis.javaの実装：
```java
Address entryPoint = f.getEntryPoint();  // 仮想アドレス
Address imageBase = currentProgram.getImageBase();  // 0x400000 (通常)
```

**結論**: Ghidraも **仮想アドレス（VA）** を使用

## 一致するかどうかの確認

### テスト方法

1. **同じバイナリでCAPAとGhidraを実行**
   ```bash
   # CAPA実行
   capa sample.exe -j > capa.json
   
   # Ghidra実行（autore経由）
   # → analysis.json
   ```

2. **アドレスを比較**
   ```python
   import json
   
   # CAPA
   capa = json.load(open('capa.json'))
   capa_base = capa['meta']['analysis']['base_address']['value']
   capa_funcs = [
       match[0]['value'] 
       for rule in capa['rules'].values() 
       for match in rule.get('matches', [])
   ]
   
   # Ghidra
   ghidra = json.load(open('analysis.json'))
   ghidra_base = int(ghidra['sample']['image_base'], 16)
   ghidra_funcs = [
       int(f['entry'], 16) 
       for f in ghidra['functions']
   ]
   
   # 比較
   print(f"CAPA base:  {hex(capa_base)}")
   print(f"Ghidra base: {hex(ghidra_base)}")
   print(f"Match: {capa_base == ghidra_base}")
   
   # 関数アドレスの共通部分
   common = set(capa_funcs) & set(ghidra_funcs)
   print(f"Common functions: {len(common)}")
   ```

### 期待される結果

#### Case A: 完全一致（理想）
```
CAPA base:  0x400000
Ghidra base: 0x400000
Match: True
Common functions: 多数
```
→ **そのまま使える**

#### Case B: Base Addressは一致するが関数が少ない
```
CAPA base:  0x400000
Ghidra base: 0x400000
Match: True
Common functions: 数個
```
→ **一致するが、CAPAが検出する関数がGhidraより少ない（正常）**

#### Case C: Base Addressが異なる
```
CAPA base:  0x400000
Ghidra base: 0x10000000
Match: False
```
→ **変換が必要** → 後述の対策を実施

## 対策（アドレスが一致しない場合）

### Option 1: CAPA出力を正規化
```python
# backend/app.py で capa.json を読み込み時に変換
def normalize_capa_addresses(capa_json, ghidra_image_base):
    """Convert CAPA addresses to match Ghidra's addressing scheme."""
    capa_base = capa_json['meta']['analysis']['base_address']['value']
    offset = ghidra_image_base - capa_base
    
    # 全アドレスをオフセット調整
    for rule_name, rule_data in capa_json['rules'].items():
        for match in rule_data.get('matches', []):
            for loc in match:
                if loc['type'] == 'absolute':
                    loc['value'] += offset
    
    return capa_json
```

### Option 2: UIで表示時に変換
```typescript
// frontend/src/App.tsx
function convertCapaToGhidraAddress(capaAddr: number, capaBase: number, ghidraBase: number): string {
  const offset = capaAddr - capaBase;
  const ghidraAddr = ghidraBase + offset;
  return `0x${ghidraAddr.toString(16)}`;
}
```

### Option 3: 相対アドレス（RVA）で保存
- CAPAとGhidraの両方でRVAを計算
- UIでVAに変換して表示

## UI表示の提案

### CAPA検出を関数リストに統合
```
関数リスト:
  FUN_00401000
    ├ Size: 256 bytes
    ├ Win API: CreateFileA
    └ CAPA: create file, read file on Windows  ← 追加
```

### CAPA matchesをクリック可能に
- CAPAで検出されたアドレスをクリック
- → 該当関数にジャンプ

## まとめ

1. **まずは実際のバイナリで確認**
   - t32.exe で CAPA と Ghidra のアドレスを比較
   
2. **一致すれば**
   - そのまま使える
   - UI統合を進める

3. **一致しない場合**
   - 上記の対策（正規化）を実装
   - RVA変換ロジックを追加

## テスト結果（2026-01-28）

### テストバイナリ
- **ファイル**: t32.exe (96KB, PE 32-bit)
- **CAPA**: v7.4.0
- **Ghidra**: 11.x + ExtractAnalysis.java

### 結果

```
============================================================
CAPA vs Ghidra Address Comparison
============================================================

Base Address:
  CAPA:   0x400000
  Ghidra: 0x400000
  Match:  ✅ True

Function Count:
  CAPA:   33 functions (CAPA検出範囲)
  Ghidra: 296 functions (全関数)

Common Functions: 29 (88% overlap)

First 10 common addresses:
  0x401000, 0x40106a, 0x4010d4, 0x401116, 0x4012ee
  0x40139d, 0x4013da, 0x40140a, 0x4014c0, 0x401617

CAPA-only: 4 functions
Ghidra-only: 267 functions (Ghidraの方が多く検出)
```

### 結論

**✅ アドレスは完全に互換性があります**

- Base Addressが一致（`0x400000`）
- 関数アドレスが一致（仮想アドレス形式）
- **アドレス変換は不要**

### 実装への影響

- CAPAのアドレスをそのままGhidraの関数IDと突合できる
- UI統合時に変換ロジック不要
- `0x401000` (CAPA) → `FUN_00401000` (Ghidra) の対応が可能

### 注意点

- **形式の違いのみ**:
  - CAPA: 数値（`4198400` = `0x401000`）
  - Ghidra: 8桁16進文字列（`"00401000"`）
- **変換例**:
  ```python
  capa_addr = 4198400  # CAPA
  ghidra_id = f"FUN_{capa_addr:08X}"  # "FUN_00401000"
  ```

## 次のステップ

```bash
# 1. 実際のジョブで確認
cd ~/ghidrauto-llm
# 既存ジョブIDを取得
JOB_ID=<job_id>

# 2. CAPAとGhidraの出力を比較
cat work/$JOB_ID/extract/capa.json | jq '.meta.analysis.base_address'
cat work/$JOB_ID/extract/analysis.json | jq '.sample.image_base'

# 3. 関数アドレスを比較
cat work/$JOB_ID/extract/capa.json | jq '.rules | to_entries | .[0].value.matches[0][0]'
cat work/$JOB_ID/extract/analysis.json | jq '.functions[0].entry'
```

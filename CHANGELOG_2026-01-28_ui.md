# CHANGELOG - 2026-01-28 (UI / UX Improvements)

この日付の開発で入った UI/UX 系の変更まとめ。

## CFG (calls_out) 関連
- ReactFlow のカスタムノードに Handle を追加し、CFG のエッジ（線）が表示されるように修正
- レイアウトを「上→下」のピラミッド型に変更（depthごとに中央揃え）
- 縦方向の間隔（YGAP）調整
- depth を 1〜3 で切替可能（モーダル内セレクタ）
- CFG 内のノードをクリックした際に
  - CFG モーダルは閉じずに root をそのノードに変更して再描画
  - 裏の3ペイン（Disasm/Ghidra/AI）も同じ関数へ遷移
- CFG ノードのドラッグを有効化（セッション内のみ。保存はしない）

## 関数リスト / 重複表示
- `_guard_dispatch_icall` 等の重複表示対策
  - Ghidra 側の関数重複抑制を試行
  - UI 側は function `id` ベースで de-dup（同名関数が複数 entry を持つケースでも増殖しない）

## レイアウト / リサイズ問題
- モーダルの maxWidth を px 固定から `vw` ベースに変更し、ブラウザリサイズに追従
- Topbar の長い文字列（特にフルパス表示）がレイアウトを固定幅化させる問題を緩和
- Topbar 右側ボタン群の重なり/黒帯（overflowの副作用）を修正（レイアウトの調整）
- Pane の grid を `%` → `fr` ベースに変更

## コード表示
- 行数表示 `// lines=N` を本文先頭に出すのをやめ、ペインタイトル横に小さく表示
- syntax highlight（highlight.js）導入
- 速度改善
  - Disassembly の per-line highlight を無効化
  - Ghidra はブロック単位で 1回 highlight（大幅改善）
- AI pseudocode の先頭 `/* ... */` コメントブロックを表示から除去
- AI ペインの summary を折りたたみ可能に

## Call ranking
- Most Called Functions（call ranking）を AI ペイン内表示からモーダル表示へ変更

## Pane 操作
- Disassembly ペインを左に折りたたみ可能に（極細ストリップまで縮小）

---

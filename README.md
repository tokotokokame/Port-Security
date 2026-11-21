# Port-Security

ポート番号を起点に「攻撃の特徴 → MITRE ATT&CK 技術 → 検知戦略 → ログ調査 → 根拠資料」を一貫して引けるサイバーセキュリティ・データベースです。スマートフォン向け検索ツールのデータ層として使います。

> ⚠️ 教育・防御目的のデータです。攻撃コードや実ネットワークへの操作手順は含みません。

## 構成

| パス | 内容 |
|---|---|
| `data/` | 正本データ（JSON 9種）。編集はここだけ |
| `dist/port_index.json` | アプリ用の結合済みインデックス（自動生成・1ポート=1レコード） |
| `docs/DATA_DICTIONARY.md` | スキーマ・ID体系・リンク構造 |
| `docs/VALIDATION_REPORT.md` | 整合性検証と到達率・不足リスト（自動生成） |
| `docs/DATA_UPDATE_GUIDE.md` | データ追加・更新の手順 |
| `tools/validate.py` | 参照整合性・根拠ルールの検証（標準ライブラリのみ） |
| `tools/test_validate.py` | 検証器の自己テスト（壊したデータを確実に検出するか） |
| `tools/build_index.py` | インデックスとレポートの生成 |
| `tools/migrate_v3_to_v4.py` | v3→v4 移行スクリプト（修正内容の監査記録） |

## 使い方

```bash
python3 tools/validate.py data          # 整合性検証（エラーがあれば exit 1）
python3 -m unittest discover -s tools   # 検証器の自己テスト
python3 tools/build_index.py            # dist/ と docs/VALIDATION_REPORT.md を再生成
```

GitHub Actions（`.github/workflows/validate.yml`）が push / PR ごとに上記を実行し、生成物のコミット漏れも検出します。

## アプリからの参照

`dist/port_index.json` を読み、`port_number` と `transport_protocol` で1件引けば、関連する全情報が入っています。

- `logs[].match` … 関連度（`DET公式監視ポート一致` > `DETサービス名から推定` > `攻撃手法経由` > `境界機器ログ(全ポート共通)`）。強い順に並んでいます
- `gaps` … そのポートで未整備の情報（UIで「未作成」表示に使えます）
- `certainty` / `unconfirmed_notes` … 根拠の確度

## 現状

到達率・不足の一覧は [`docs/VALIDATION_REPORT.md`](docs/VALIDATION_REPORT.md) を参照。リスク評価・サービス辞書・ポート別の一次資料が主な未整備領域です。

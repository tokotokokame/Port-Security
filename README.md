# Port-Security

ポート番号を起点に「攻撃の特徴 → MITRE ATT&CK 技術 → 検知戦略 → ログ調査 → 根拠資料」を一貫して引けるサイバーセキュリティ・データベースです。スマートフォン向け検索ツールのデータ層として使います。

> ⚠️ 教育・防御目的のデータです。攻撃コードや実ネットワークへの操作手順は含みません。

## Android アプリ

[Releases](https://github.com/tokotokokame/Port-Security/releases/latest) から `port-security-*-arm64.apk` をダウンロードしてインストールします（古い32bit端末は `armv7` 版）。通信は行わず、データはすべてアプリに同梱されています。

- **収録範囲**: IANA 登録の全ポートと、セキュリティ上重要なポート160件の詳細
- **検索**: ポート番号、通信方式（`445/tcp` など）、サービス名、MITRE ID、イベントID、ツール名
- **詳細検索設定**:
  - 基本: 通信方式・区分・番号範囲・詳細ありのみ
  - 脅威: リスク・攻撃手法・攻撃ツール・MITRE 戦術
  - 調査: ログ基盤・確度
  - 並び替え
- **ポート詳細**: `概要 / 攻撃 / tools / att&ck / logs / src` のタブで、ATT&CK の検知戦略が指定するログ源（例: `WinEventLog:Security EventCode=4769`）まで表示
- **逆引き**: 攻撃手法・攻撃ツール・ログ基盤（Windows / Linux / macOS / ESXi / Hyper-V / VirtualBox / FortiGate / NEC IX）から対象ポートを引ける
- **攻撃ツール**: Impacket・Mimikatz・smbclient など18件を、検知に使う痕跡だけで収録

ソースは `app/` にあります。セキュリティ方針と点検内容は [SECURITY.md](SECURITY.md) を参照してください。

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

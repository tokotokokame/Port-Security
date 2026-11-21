# 開発者向け情報

## 構成

| パス | 内容 |
|---|---|
| `data/` | 正本データ（JSON）。編集はここだけ |
| `data/raw/iana/` | IANA 公式 CSV（`.github/workflows/iana.yml` で取得） |
| `dist/` | アプリ用インデックス（自動生成）: `ports.json` / `kb.json` / `iana.json` |
| `app/` | Flutter アプリ。`app/assets/data/` は `dist/` と同一内容 |
| `docs/DATA_DICTIONARY.md` | スキーマ・ID 体系・リンク構造・根拠（evidence） |
| `docs/RISK_RUBRIC.md` | リスク評価の基準 |
| `docs/DATA_UPDATE_GUIDE.md` | データ追加・更新の手順 |
| `docs/VALIDATION_REPORT.md` | 整合性検証と到達率・不足リスト（自動生成） |
| `tools/validate.py` | 参照整合性・根拠ルールの検証（標準ライブラリのみ） |
| `tools/test_validate.py` | 検証器の自己テスト（壊したデータを確実に検出するか） |
| `tools/build_index.py` | `dist/`・アプリ同梱データ・レポートの生成 |
| `tools/import_mitre.py` | MITRE ATT&CK STIX からの技術・検知戦略の取り込み |
| `tools/check_manifest.py` | リリース APK のセキュリティ点検 |
| `tools/make_icon.py` | アプリアイコン（ドット絵）の生成 |

## データの検証と生成

```bash
python3 tools/validate.py data          # 整合性検証（エラーがあれば exit 1）
python3 -m unittest discover -s tools   # 検証器の自己テスト
python3 tools/build_index.py            # dist/・app/assets/data/・docs/VALIDATION_REPORT.md を再生成
```

`.github/workflows/validate.yml` が push / PR ごとに上記を実行し、生成物のコミット漏れも検出します。

## アプリのビルド

```bash
cd app
flutter analyze
flutter test
flutter build apk --release --split-per-abi
```

`main` への push で `.github/workflows/android.yml` が解析・テスト・APK 点検を行い、Releases に `v1.0.<run番号>` として公開します。

### 署名（任意）
Secrets に次を設定するとリリース鍵で署名されます。未設定の場合はデバッグ鍵で署名され、ビルドごとに鍵が変わるため、更新時にアンインストールが必要になります。

| Secret | 内容 |
|---|---|
| `ANDROID_KEYSTORE_BASE64` | keystore を base64 化したもの |
| `ANDROID_KEYSTORE_PASSWORD` | keystore のパスワード |
| `ANDROID_KEY_ALIAS` | 鍵のエイリアス |
| `ANDROID_KEY_PASSWORD` | 鍵のパスワード |

## インデックスの読み方（`dist/ports.json`）

1 ポート = 1 レコードで、`n`（番号）と `t`（`tcp` / `udp`）で引きます。

- `logs[]` … 関連するログ調査。`rank`（0 が最も強い）の順に並び、`match` が理由、`via` が経路です。rank の意味は [DATA_DICTIONARY.md](DATA_DICTIONARY.md) を参照
- `evidence` … ポート固有の根拠（判定・確認できた内容・資料 ID）
- `gaps` … そのポートで未整備の情報
- `certainty` / `notes` … 根拠の確度と未確認事項

到達率・不足の一覧は [VALIDATION_REPORT.md](VALIDATION_REPORT.md) を参照してください。

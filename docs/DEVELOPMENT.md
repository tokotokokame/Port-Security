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
| `data/schemas/` | JSON Schema（生成物。仕様は `docs/DATA_SCHEMA_SPEC.md`） |
| `data/raw/mitre/` `data/raw/cve/` `data/raw/kev/` | ATT&CK・CVE・KEV の公式データ |
| `docs/DATA_QUALITY_STANDARD.md` | 品質の合格基準 |
| `docs/DATA_CHANGELOG.md` | データ変更履歴（ID の削除・改名は必須記載） |
| `docs/baseline/` | v1.1 開始時点の基準（全 ID・件数・検査結果） |
| `docs/MITRE_VALIDATION_REPORT.md` / `docs/CVE_VALIDATION_REPORT.md` | 照合レポート（自動生成） |
| `docs/TEST_REPORT.md` / `docs/RELEASE_CHECKLIST.md` | 試験結果・リリース手順 |
| `tools/validate.py` | 参照整合性・根拠ルールの検証（標準ライブラリのみ） |
| `tools/quality.py` | 品質基準の検査（Q-JSON〜Q-COUNT） |
| `tools/test_validate.py` / `tools/test_quality.py` | 不正データ注入テスト（壊したデータを確実に検出するか） |
| `tools/build_index.py` | `dist/`・アプリ同梱データ・レポートの生成 |
| `tools/make_schemas.py` | JSON Schema と DATA_SCHEMA_SPEC.md の生成 |
| `tools/import_mitre.py` / `tools/mitre_ids.py` | MITRE ATT&CK STIX からの取り込み・ID カタログ |
| `tools/fetch_cve.py` / `tools/import_cve.py` / `tools/cve_catalog.py` | CVE・KEV の取得・生成・該当条件 |
| `tools/freshness.py` | 一次データの鮮度チェック（週次 CI） |
| `tools/apply_v11.py` | v1.1 のデータ修正（再実行しても同じ結果） |
| `tools/check_manifest.py` | リリース APK のセキュリティ点検 |
| `tools/make_icon.py` | アプリアイコン（ドット絵）の生成 |

## データの検証と生成

```bash
pip install -r tools/requirements.txt   # jsonschema（バージョン固定）
python3 tools/validate.py data          # 整合性検証（エラーがあれば exit 1）
python3 tools/quality.py                # 品質基準（エラーがあれば exit 1）
python3 -m unittest discover -s tools   # 不正データ注入テスト
python3 tools/make_schemas.py           # スキーマと仕様書
python3 tools/build_index.py            # dist/・app/assets/data/・各レポートを再生成
```

- `validate.yml`（PR / main）: 上記をすべて実行し、生成物のコミット漏れも検出します。
- `android.yml`: 同じ品質ゲートを通らないとビルド・リリースしません。
- `freshness.yml`（毎週月曜）: IANA・ATT&CK・CVE・KEV が更新されていたら失敗して知らせます（自動コミットはしません）。

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

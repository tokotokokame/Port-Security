# DATA_UPDATE_GUIDE

## 原則

1. 編集するのは `data/` だけです。`dist/`・`app/assets/data/`・`data/schemas/`・`docs/*_REPORT.md`・`docs/DATA_SCHEMA_SPEC.md` は生成物なので、手で直しません。
2. 主張には根拠を付けます。IANA はポート割当の根拠であり、攻撃・検知の記述の根拠にはなりません。
3. 確認できない内容は `certainty: 一部確認` とし、`unconfirmed_notes` に不足を書きます。
4. 既存 ID を削除・改名するときは `docs/DATA_CHANGELOG.md` に ID と理由を書きます（書かないと CI が失敗します）。
5. 出典を追加したら、内容を確認したうえで `verification_status`・`access_date`・`reverified_v4: true`、確認に使った原文があれば `verified_via` を記録します。

## ポートを追加する

1. `data/ports.json` にレコードを追加します。ID は `PORT-{5桁}-{通信方式}` です。
2. `service_id` と `risk_id` は、該当するレコードがなければ `null` にします。
3. `technique_ids` は `data/mitre_techniques.json` にある ID（またはそのサブ技術）だけを使います。
4. 新しい技術が必要なときは、先に attack.mitre.org で確認し、`mitre_techniques.json` と `sources.json`（`SRC-MITRE-T####`）を追加します。

## リスク評価・サービス辞書を追加する

`port_risks.json` / `services.json` に追加したら、対応する `ports` レコードの `risk_id` / `service_id` も更新します。片方だけだと validate が失敗します。

## 一次データの更新（週次の data-freshness が知らせます）

| 対象 | 手順 |
|---|---|
| IANA | GitHub Actions の `refresh-iana` を手動実行 → 取り込まれた CSV で quality.py が IANA 名・プロトコル番号を照合 |
| ATT&CK | 公式 STIX を取得 → `python3 tools/mitre_ids.py enterprise.json ics.json > data/raw/mitre/attack_catalog.json` → `python3 tools/import_mitre.py enterprise.json`。DET0118 の監視ポートは `tools/mitre_catalog.py` で (番号, 通信方式) と `DET0118_TRANSPORT` を照合 |
| CVE / KEV | `python3 tools/fetch_cve.py` → `python3 tools/import_cve.py`。CVE を追加するときは `tools/cve_catalog.py` に該当条件と言及しているリスク評価を書く |

## 反映手順

```bash
pip install -r tools/requirements.txt    # jsonschema（初回のみ）
python3 tools/validate.py data          # 参照整合性
python3 tools/quality.py                # 品質基準（docs/DATA_QUALITY_STANDARD.md）
python3 -m unittest discover -s tools   # 不正データ注入テスト
python3 tools/make_schemas.py && python3 tools/build_index.py
git add -A && git commit -m "Data: ..."
```

## 優先して整備するもの

`docs/VALIDATION_REPORT.md` の「ポート別の不足」が作業リストです。

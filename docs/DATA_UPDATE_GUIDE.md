# DATA_UPDATE_GUIDE

## 原則

1. 編集するのは `data/` だけです。`dist/` と `docs/VALIDATION_REPORT.md` は生成物なので、手で直しません。
2. 主張には根拠を付けます。IANA はポート割当の根拠であり、攻撃・検知の記述の根拠にはなりません。
3. 確認できない内容は `certainty: 一部確認` とし、`unconfirmed_notes` に不足を書きます。

## ポートを追加する

1. `data/ports.json` にレコードを追加します。ID は `PORT-{5桁}-{通信方式}` です。
2. `service_id` と `risk_id` は、該当するレコードがなければ `null` にします。
3. `technique_ids` は `data/mitre_techniques.json` にある ID（またはそのサブ技術）だけを使います。
4. 新しい技術が必要なときは、先に attack.mitre.org で確認し、`mitre_techniques.json` と `sources.json`（`SRC-MITRE-T####`）を追加します。

## リスク評価・サービス辞書を追加する

`port_risks.json` / `services.json` に追加したら、対応する `ports` レコードの `risk_id` / `service_id` も更新します。片方だけだと validate が失敗します。

## MITRE ATT&CK の更新（年2回のリリース時）

1. `mitre_techniques.json` の各技術の `version` / `last_modified` / `detection_strategy_ids` を公式ページと照合します。
2. `detection_strategies.json` の analytic ID と監視ポートを照合します。ポートが明記されていなければ `port_basis: inferred` にします。
3. 照合した資料の `sources.json` で `access_date` を更新します。

## 反映手順

```bash
python3 tools/validate.py data
python3 -m unittest discover -s tools
python3 tools/build_index.py
git add data dist docs && git commit -m "Data: ..."
```

## 優先して整備するもの

`docs/VALIDATION_REPORT.md` の「ポート別の不足」が作業リストです。

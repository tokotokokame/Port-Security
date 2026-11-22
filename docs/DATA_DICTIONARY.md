# DATA_DICTIONARY（v1.2）

フィールド単位の必須・型・制約は自動生成の [DATA_SCHEMA_SPEC.md](DATA_SCHEMA_SPEC.md)（JSON Schema 本体は `data/schemas/`）を正とする。

## ファイルと主キー

| ファイル | 主キー形式 | 内容 |
|---|---|---|
| `ports.json` | `PORT-{5桁}-{TCP\|UDP\|SCTP\|DCCP}` | ポート単位のマスター（番号 + 通信方式で 1 レコード） |
| `services.json` | `SRV-{略称}` | サービス辞書 |
| `protocols.json` | `PROTO-{名前}` | IP プロトコル辞書（`ip_protocol_number` と `layer` を分離） |
| `attack_patterns.json` | `ATK-{略称}` | 攻撃手法・検知方法 |
| `port_risks.json` | `RISK-{5桁}-{通信方式}` | ポート別リスク評価 |
| `log_investigation.json` | `LOG-{基盤}-{識別子}` | ログ調査手順 |
| `mitre_techniques.json` | `T####` | ATT&CK 技術（サブ技術は `subtechniques` に内包） |
| `detection_strategies.json` | `DET####` | ATT&CK 検知戦略と analytic |
| `tools.json` | `TOOL-{名前}` | 攻撃ツール（検知の痕跡のみ。使い方は含まない） |
| `mitre_software.json` | `S####` | ATT&CK に収録されたツール情報（公式 STIX から生成） |
| `vulnerabilities.json` | `CVE-YYYY-NNNN` | CVE（製品・バージョン経由。ポートに直接紐付けない） |
| `sources.json` | `SRC-{略称}` | 根拠資料 |
| `raw/iana/service-names-port-numbers.csv` | — | IANA ポート台帳（CI の `refresh-iana` が取得） |
| `raw/iana/protocol-numbers-1.csv` | — | IANA Protocol Numbers 台帳（同上） |
| `raw/mitre/attack_catalog.json` | — | ATT&CK 公式 STIX の ID・名称・廃止状態（`tools/mitre_ids.py`） |
| `raw/cve/*.json` / `raw/kev/kev_subset.json` | — | CVE 公式レコードと CISA KEV（`tools/fetch_cve.py`） |
| `schemas/*.schema.json` | — | JSON Schema（`tools/make_schemas.py`） |

## 生成の流れ

1. `tools/import_mitre.py <enterprise-attack.json>`: 参照中の技術・ツールについて、技術・検知戦略・analytic・ソフトウェアを ATT&CK 公式 STIX から再生成します。
2. `tools/validate.py`: 整合性を検証します。
3. `tools/build_index.py`: `dist/` と `app/assets/data/` に `ports.json` / `kb.json` / `iana.json` を出力します。

`tools/apply_v5.py`・`v5_catalog.py`・`v5_ports.py` は v4→v5 の拡充記録です（監査用）。

## ports の `evidence`（根拠の確認記録）

`[{source_id, technique, kind, examples, keyword}]` の形式です。各項目は「その出典が、このポートのどの主張を裏付けるか」を記録します。

- `kind`:
  - `技術説明`: ATT&CK の技術の説明文にサービス名がある
  - `手順例`: ATT&CK の実際の使用例にある
  - `ATT&CK検知戦略`: ATT&CK の analytic がポートを監視対象に挙げている（`examples` に analytic ID）
  - `公式文書`: ベンダーの文書にある
  - `政府勧告`: 政府機関の勧告にある
- 確認済みのポートは evidence が必須（quality.py Q-VERIFIED）

## ports の `technique_basis`（ATT&CK 技術との関連区分）

`[{technique, relation, via, note, source_type}]`。ポート番号と技術を直接結び付けず、経路を持たせる。quality.py がデータと突き合わせて検証する（Q-ASSOC）。

| relation（v1.2） | via | 条件 |
|---|---|---|
| `direct` | 出典 ID | evidence がその技術を名指ししている |
| `generic` | 攻撃手法 ID | `port_relation=generic` の攻撃手法（どの公開サービスにも当てはまる）がその技術を持つ |
| `inferred` | 攻撃手法 ID / サービス | `port_relation=service_specific` の攻撃手法がその技術を持つ、またはサービスの性質から対象になる（`note` で説明） |
| `unverified` | — | 参考。`note` 必須（一次資料未付与と明記） |

`source_type`: `stix`（ATT&CK 公式の記述）/ `document`（他の一次資料）/ `curation`（アプリ内の関連付け）。
v1.1 の `attack_pattern` / `service` / `reference` は、それぞれ generic または inferred / inferred / unverified に移した。
- `examples`: 手順例を記載した攻撃グループやマルウェア
- `keyword`: 一致した語、または確認した要点

`evidence` で引用する出典は、必ず `source_ids` にも含めます（validate.py が検査します）。

生成は `tools/evidence_attack.py`（ATT&CK 公式記述との照合）→ `tools/apply_evidence.py` / `apply_evidence_docs.py`（人によるレビューの結果）の順です。

## ログ調査の関連度（`ports.json` の `logs[].rank`）

| rank | 意味 |
|---|---|
| 0 | DET の公式監視ポートに (番号, 通信方式) で一致 |
| 1 | 公式文書でポートが指定されている（Hyper-V / VirtualBox など） |
| 2 | DET のサービス名から推定したポート |
| 3 | 技術 → 検知戦略 → analytic のプラットフォームで対応 |
| 4 | 攻撃手法・ツールの経由 |
| 5 | 境界機器ログ（全ポート共通） |

`logs[].class`（v1.2）: rank 1 → A、rank 0・2 → B（DET0118 の analytic 専用ログのみ）、rank 3 → B'、rank 4・5 → C/D。
同じ analytic でもプラットフォーム共通ログは B'。`log_class` はポートで最良の分類。「ポート固有のログなし」は A・B がないときだけ。

## analytic の `log_links`（v1.2）

`[{log_id, basis}]`。`basis=det0118_analytic` は DET0118 の analytic 専用ログ（LOG-*-AN03xx）、`platform_generic` はプラットフォーム共通ログ（LOG-WIN-SECURITY / LOG-LIN-GENERIC / LOG-MAC-GENERIC / LOG-ESXI-GENERIC / 境界機器）。`log_investigation_ids` は互換のため残す（log_links の log_id と一致）。

## リンク構造（すべて ID による外部キー）

```
ports ──service_id──▶ services
  │  ──risk_id─────▶ port_risks          (port_risks 側にもポート番号・通信方式あり。双方一致を検証)
  │  ──protocol_id─▶ protocols
  │  ──attack_pattern_ids─▶ attack_patterns ──log_investigation_ids─▶ log_investigation
  │  ──technique_ids─▶ mitre_techniques ──detection_strategy_ids─▶ detection_strategies
  │                                                     └ analytics[].log_investigation_ids ─▶ log_investigation
  └  ──source_ids─▶ sources                                   (log_investigation.analytics_ids と双方向)
```

- 攻撃手法の対象ポートは `ports.attack_pattern_ids` だけが正本です（v3の `target_ports` は二重管理でずれていたため廃止。逆引きはインデックスで生成）。
- `technique_ids` には `T####` / `T####.###` のみを入れます。`DET####` は検知戦略ファイルへ分離しました。
- `source_urls` は廃止しました。URL は `sources.json` から引きます。

## analytic の `port_basis`

| 値 | 意味 |
|---|---|
| `official` | 公式ページにポート番号が明記されている |
| `inferred` | 公式はサービス名のみ。標準ポートを推定（例: DET0118/AN0328） |
| `none` | ポート情報なし |

## analytic の `monitored_ports` と `transport_basis`

`monitored_ports` は `[[番号, 通信方式], …]`。ポートとの照合は (番号, 通信方式) の一致のみで、番号だけでは紐付けない。

| transport_basis | 意味 |
|---|---|
| `stated` | analytic 本文に通信方式がある（例: AN0329 の `tcp/427`） |
| `service_default` | 番号のみの記載。挙げられたサービスの標準通信方式（SMB・RDP・WinRM・SSH・VNC → TCP） |
| `none` | 監視ポートなし |

## vulnerabilities（CVE）

- `affected` / `cvss` / `published` / `updated` / `kev` は `data/raw/` の公式レコードから `tools/import_cve.py` が生成する。手編集すると quality.py が検出する（Q-CVE）
- `condition`（該当条件）と `risk_ids` だけを `tools/cve_catalog.py` で管理する
- ポート番号のフィールドは持たない

## log_investigation の `port_scope`

- `analytics` … DET0118 の analytic 専用のホストログ（LOG-WIN-AN0327 など）
- `platform` … プラットフォーム共通のログ（v1.2。旧 `any_windows` を含む）。ポートとは直接関連付けない
- `listed` … 公式文書がポートを明示（`ports` に一覧）
- `any` … 境界機器ログ（FortiGate / NEC IX）。全ポート共通で適用

## log_investigation の `vendor_logs`（v1.2）

`[{vendor, product, firmware_versions, log_type, log_subtype, log_id, message, fields, cli_commands, source_ids, verification_status, notes}]`。
版ごとに別の項目にし、出典はページ単位。確認済みの fields・cli_commands・版は `data/raw/vendor/fortios_evidence.json`（CI で取得した公式ページの抽出結果）にあることを Q-VENDOR が検査する。`common_fields` / `vendor_specific_fields` には確認済みの vendor_logs にあるフィールドだけを書く。

## port_risks の `service_risk` / `exposure_condition` / `review`（v1.2）

- `risk_level`: 編集判断（互換のため残す。インターネット露出を前提）
- `service_risk`: `{level, factors, reason, source_ids, status}`。一次資料で確認できた要素（KEV・ATT&CK・政府資料・ベンダー資料）だけで判定。要素がなければ `未評価`（低リスクという意味ではない）。規則は RISK_RUBRIC
- `exposure_condition`: `{assumed, raises, lowers, notes}`
- `review`: High 再検証の結果（`previous_level`・`result`・根拠 `evidence`・変更理由 `reason`）

## attack_patterns の確認状態（v1.2）

- `attack_mapping_status`: ATT&CK 技術への対応付け（公式 STIX と照合）
- `content_verification_status`: 説明・特徴・検知・対策の本文
- `content_source_ids`: 本文の根拠資料
- `port_relation`: generic / service_specific
- `certainty` は互換用の総合値（弱い方に合わせる）

## sources の `scope` と `reverified_v4`

`scope`: `port_assignment` / `protocol_assignment` / `service` / `attack_technique` / `detection` / `threat_advisory` / `threat_guidance` / `log_format` / `reference` / `vulnerability`、v1.2 で追加: `vendor_security` / `tool_documentation` / `technical_documentation` / `government_guidance` / `research_report` / `attack_framework` / `vulnerability_database`

`reverified_v4`: 確認状態が確認済みか（v1.2 では `verified_via` から決まる）。

v1.2 の確認方法: `verified_via`（original_document / official_api / official_stix / official_repository / search_result / not_verified）、`verified_url`（実際に確認した原文の所在）、`verified_date`、`verified_by`（manual_review / automated_import）、`verified_notes`（確認した範囲）。
参照状況: `usage_status`（使用中 / 未使用・将来利用予定 / 未使用・再確認待ち / 廃止）、`usage_notes`、統合した出典は `merged_into`。

## 値がないことの表し方（v1.2）

| 表記 | 意味 |
|---|---|
| `null` | その項目が存在しない・該当しない（例: `event_code` のないログ源、未登録の `service_id`） |
| `""` | 文字列の項目で値を持たない（例: 根拠を確認できていない vendor_logs の `log_id`）。理由は同じレコードの notes / unconfirmed_notes に書く |
| `[]` | 一覧が 0 件（確認済みの項目がない場合も含む。未確認の値を推測で埋めない） |
| `未確認` / `未評価` | 確認・評価をしていない、または根拠がない。空とは区別する |

## certainty の判定ルール（validate.py が強制）

| 値 | 条件 |
|---|---|
| `確認済み` | `reverified_v4=true` かつ脅威系 scope（`attack_technique` / `detection` / `threat_advisory`）の資料を `source_ids` に持つ。ログは `detection` / `log_format` |
| `一部確認` | 上記を満たさない。`unconfirmed_notes` に不足を必ず記載 |
| `未確認` | 根拠なし。`unconfirmed_notes` 必須 |

DET0118 をポートの根拠に引用できるのは、DET0118 の公式監視ポート（445, 135, 3389, 5985, 5986, 1433, 3306, 427, 443, 902, 5989, 22, 5900, 8080, 8443）だけです。

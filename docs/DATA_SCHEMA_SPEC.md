# DATA_SCHEMA_SPEC — データスキーマ仕様（自動生成: tools/make_schemas.py）

スキーマ本体は `data/schemas/<file>.schema.json`（JSON Schema 2020-12）。CI で全レコードを検査する（Q-SCHEMA）。
未定義のフィールドは追加できない（`additionalProperties: false`）。ID 体系は変更しない。

## 検証状態の対応（計画書の設計例との対応）

| 設計例 | 本データ |
|---|---|
| verification.status | `certainty`（確認済み / 一部確認 / 未確認） |
| verification.verified_at | `verified_date` |
| evidence[].source_id / claim | `evidence[].source_id` / `evidence[].keyword` |
| evidence[].scope | 出典側の `sources.scope` |
| evidence[].verification_status | 出典側の `sources.verification_status` |
| unverified_items | `unconfirmed_notes` |
| データ更新日・変更履歴 | `docs/DATA_CHANGELOG.md` と git 履歴 |

## ports.json — 詳細付きポート（1 レコード = 番号 + 通信方式）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^PORT-\d{5}-(TCP|UDP|SCTP|DCCP)$` | ID |
| `port_number` | ○ | `integer` | ポート番号 |
| `transport_protocol` | ○ | `["TCP", "UDP", "SCTP", "DCCP"]` | 通信方式 |
| `protocol_number` | ○ | `[6, 17, 132, 33]` | 通信方式の IP プロトコル番号（TCP=6, UDP=17, SCTP=132, DCCP=33） |
| `protocol_id` | ○ | `^PROTO-[A-Z0-9]+$` | protocols.id |
| `service_name` | ○ | `string` | IANA 登録名。未登録は '(未登録)' |
| `formal_name` | ○ | `string` | 正式名・慣用名 |
| `iana_description` | ○ | `string` | IANA 台帳の Description |
| `category` | ○ | `^[A-Z0-9]+$` | 区分（WEB, AUTH など） |
| `purpose` | ○ | `string` | 用途 |
| `technical_description` | ○ | `string` | 技術説明 |
| `normal_usage_examples` | ○ | `string` | 正常利用例 |
| `malicious_exploitation_cases` | ○ | `string` | 悪用例 |
| `suspicious_traffic_features` | ○ | `string` | 不審な通信の特徴 |
| `investigation_checkpoints` | ○ | `string` | 調査観点 |
| `recommended_defenses` | ○ | `string` | 対策 |
| `attack_pattern_ids` | ○ | `array` | 攻撃手法 ID |
| `technique_ids` | ○ | `array` | ATT&CK 技術 ID（technique_basis に関連区分） |
| `technique_basis` | ○ | `array` | 技術ごとの関連区分と経路 |
| `service_id` | ○ | `anyOf` | services.id |
| `risk_id` | ○ | `^RISK-\d{5}-(TCP|UDP|SCTP|DCCP)$` | port_risks.id |
| `evidence` | — | `array` | ポート固有の根拠。確認済みでは必須 |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## port_risks.json — ポートのリスク評価

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^RISK-\d{5}-(TCP|UDP|SCTP|DCCP)$` | ID |
| `port_number` | ○ | `integer` | ポート番号 |
| `transport_protocol` | ○ | `["TCP", "UDP", "SCTP", "DCCP"]` | 通信方式 |
| `service_name` | ○ | `string` | IANA 登録名 |
| `risk_level` | ○ | `["Critical", "High", "Medium", "Low"]` | リスク |
| `reason_targeted` | ○ | `string` | 狙われる理由 |
| `evaluation_factors` | ○ | `anyOf` | 評価要素（v3 形式 / v5 形式） |
| `suspicious_indicators` | ○ | `string` | 不審な兆候 |
| `investigation_focus` | ○ | `string` | 調査の焦点 |
| `mitigation_controls` | ○ | `string` | 対策 |
| `technique_ids` | ○ | `array` | ATT&CK 技術 ID |
| `review` | — | `object` | v1.2 の High 再検証の結果と根拠 |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## services.json — サービス（プロトコル）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^SRV-[A-Z0-9-]+$` | ID |
| `service_name` | ○ | `string` | サービス名 |
| `formal_name` | ○ | `string` | 正式名 |
| `ports` | ○ | `array` | (番号, 通信方式)。参照元ポートと一致 |
| `port_number` | — | `integer` | 非推奨（v3 互換）。ports を使う |
| `transport_protocol` | — | `string` | 非推奨（v3 互換の文字列） |
| `protocol_number` | — | `integer` | 非推奨（v3 互換） |
| `purpose` | ○ | `string` | 用途 |
| `technical_description` | ○ | `string` | 技術説明 |
| `normal_usage_examples` | ○ | `string` | 正常利用例 |
| `malicious_exploitation_cases` | ○ | `string` | 悪用例 |
| `suspicious_traffic_features` | ○ | `string` | 不審な通信の特徴 |
| `investigation_checkpoints` | ○ | `string` | 調査観点 |
| `recommended_defenses` | ○ | `string` | 対策 |
| `attack_pattern_ids` | ○ | `array` | 攻撃手法 ID |
| `technique_ids` | ○ | `array` | ATT&CK 技術 ID |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## protocols.json — IP 上のプロトコル（IP プロトコル番号）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^PROTO-[A-Z0-9]+$` | ID |
| `ip_protocol_number` | ○ | `integer` | IANA Protocol Numbers の番号 |
| `protocol_number` | ○ | `integer` | 非推奨（ip_protocol_number と同値） |
| `service_name` | ○ | `string` | IANA のキーワード（小文字） |
| `formal_name` | ○ | `string` | 正式名 |
| `layer` | ○ | `["L3", "L4"]` | 階層 |
| `has_port_numbers` | ○ | `boolean` | ポート番号を持つ通信方式か |
| `transport_protocol` | ○ | `string` | 非推奨（階層の説明文。layer を使う） |
| `purpose` | ○ | `string` | 用途 |
| `technical_description` | ○ | `string` | 技術説明 |
| `normal_usage_examples` | ○ | `string` | 正常利用例 |
| `malicious_exploitation_cases` | ○ | `string` | 悪用例 |
| `suspicious_traffic_features` | ○ | `string` | 不審な通信の特徴 |
| `investigation_checkpoints` | ○ | `string` | 調査観点 |
| `recommended_defenses` | ○ | `string` | 対策 |
| `attack_pattern_ids` | ○ | `array` | 攻撃手法 ID |
| `technique_ids` | ○ | `array` | ATT&CK 技術 ID |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## attack_patterns.json — 攻撃手法

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^ATK-[A-Z0-9-]+$` | ID |
| `attack_name` | ○ | `string` | 名称 |
| `category` | ○ | `string` | 区分 |
| `description` | ○ | `string` | 概要 |
| `attack_features` | ○ | `string` | 特徴 |
| `detection_methods` | ○ | `string` | 検知方法 |
| `recommended_defenses` | ○ | `string` | 対策 |
| `technique_ids` | ○ | `array` | ATT&CK 技術 ID |
| `log_investigation_ids` | ○ | `array` | ログ調査 ID |
| `port_relation` | — | `["generic", "service_specific"]` | ポートとの関係（generic=どの公開サービスにも当てはまる） |
| `attack_mapping_status` | — | `["確認済み", "一部確認", "未確認"]` | ATT&CK 技術への対応付けの確認状態（公式 STIX との照合） |
| `content_verification_status` | — | `["確認済み", "一部確認", "未確認"]` | 説明・特徴・検知・対策の本文の確認状態 |
| `content_source_ids` | — | `array` | 本文の根拠資料 ID |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## tools.json — 攻撃ツール（検知の痕跡のみ）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^TOOL-[A-Z0-9-]+$` | ID |
| `name` | ○ | `string` | 名称 |
| `category` | ○ | `string` | 区分 |
| `mitre_software_id` | ○ | `anyOf` | ATT&CK Software ID |
| `summary` | ○ | `string` | 概要 |
| `ports` | ○ | `array` | 主なポート (番号, 通信方式) |
| `artifacts` | ○ | `array` | 検知に使う痕跡 |
| `detection` | ○ | `array` | 検知方法 |
| `attack_pattern_ids` | ○ | `array` | 攻撃手法 ID |
| `technique_ids` | ○ | `array` | 追加の ATT&CK 技術 ID |
| `log_investigation_ids` | ○ | `array` | ログ調査 ID |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## log_investigation.json — ログ調査の基盤

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^LOG-[A-Z0-9-]+$` | ID |
| `platform` | ○ | `string` | 基盤 |
| `log_sources` | ○ | `array` | ログ源（チャネル・イベント ID） |
| `common_fields` | ○ | `array` | 共通フィールド |
| `vendor_specific_fields` | ○ | `array` | 製品固有フィールド |
| `detection_analytics` | ○ | `string` | 検知ロジック |
| `investigation_procedure` | ○ | `string` | 調査手順 |
| `analytics_ids` | ○ | `array` | 対応する ATT&CK analytic |
| `port_scope` | ○ | `["analytics", "any", "platform", "listed"]` | ポートとの対応方法（analytics=DET0118 の analytic 専用 / platform=プラットフォーム共通・ポート固有でない / any=境界機器 / listed=公式文書がポートを明示） |
| `ports` | ○ | `array` | port_scope=listed のときの (番号, 通信方式) |
| `vendor_logs` | — | `array` | ベンダー機器のログ定義（版・種別・ID・フィールド・CLI ごとに出典を持つ） |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## mitre_techniques.json — ATT&CK 技術（公式 STIX から生成）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^T\d{4}$` | ID |
| `name` | ○ | `string` | 名称 |
| `tactics` | ○ | `array` | 戦術 |
| `version` | ○ | `string` | 版 |
| `created_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 作成日 |
| `last_modified` | ○ | `^\d{4}-\d{2}-\d{2}$` | 更新日 |
| `detection_strategy_ids` | ○ | `array` | 検知戦略 ID |
| `subtechniques` | ○ | `array` | サブ技術 |
| `url` | ○ | `^https://attack\.mitre\.org/` | 公式ページ |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## detection_strategies.json — ATT&CK 検知戦略（公式 STIX から生成）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^DET\d{4}$` | ID |
| `name` | ○ | `string` | 名称 |
| `technique_ids` | ○ | `array` | 対象技術 |
| `version` | ○ | `string` | 版 |
| `created_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 作成日 |
| `last_modified` | ○ | `^\d{4}-\d{2}-\d{2}$` | 更新日 |
| `analytics` | ○ | `array` | analytic |
| `url` | ○ | `^https://attack\.mitre\.org/` | 公式ページ |
| `source_ids` | ○ | `array` | 根拠資料 ID |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 確認日 |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項 |

## mitre_software.json — ATT&CK Software（公式 STIX から生成）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^S\d{4}$` | ID |
| `name` | ○ | `string` | 名称 |
| `type` | ○ | `["malware", "tool"]` | 種別 |
| `description` | ○ | `string` | 説明 |
| `technique_ids` | ○ | `array` | uses 関係の技術 |
| `url` | ○ | `^https://attack\.mitre\.org/` | 公式ページ |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

## sources.json — 根拠資料

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `source_id` | ○ | `^SRC-[A-Z0-9-]+$` | ID |
| `title` | ○ | `string` | 資料名 |
| `publisher` | ○ | `string` | 発行者 |
| `url` | ○ | `^https://` | URL（https のみ） |
| `document_type` | ○ | `string` | 資料種別 |
| `applicable_data` | ○ | `string` | 適用対象 |
| `publication_date` | ○ | `anyOf` | 公開日 |
| `last_updated` | ○ | `anyOf` | 更新日 |
| `access_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 確認日 |
| `verification_status` | ○ | `["確認済み", "一部確認", "未確認"]` | 内容の確認状態 |
| `notes` | ○ | `string` | 確認した内容 |
| `scope` | ○ | `array` | 根拠として使える範囲 |
| `reverified_v4` | ○ | `boolean` | 内容を再確認済みか（確認済みでは true 必須） |
| `verified_via` | — | `["original_document", "official_api", "official_stix", "official_repository", "search_result", "not_verified"]` | 確認方法。search_result は原文確認として扱わない |
| `verified_url` | — | `string` | 実際に確認した原文の所在（URL または data/raw のパス） |
| `verified_date` | — | `^\d{4}-\d{2}-\d{2}$` | 確認方法を記録した日 |
| `verified_by` | — | `["manual_review", "automated_import"]` | 確認者 |
| `verified_notes` | — | `string` | 確認した範囲。URL が存在するだけでは主張の根拠にならない |
| `usage_status` | — | `["使用中", "未使用・将来利用予定", "未使用・再確認待ち", "廃止"]` | 参照状況 |
| `usage_notes` | — | `string` | 未使用の理由 |
| `merged_into` | — | `^SRC-[A-Z0-9-]+$` | 統合先の出典 ID（ID は互換のため残す） |

## vulnerabilities.json — CVE（製品・バージョン経由。ポートに直接紐付けない）

| フィールド | 必須 | 型・制約 | 説明 |
|---|---|---|---|
| `id` | ○ | `^CVE-\d{4}-\d{4,7}$` | ID |
| `title` | ○ | `string` | CVE レコードの題名 |
| `description` | ○ | `string` | CNA の説明（英語原文の要約） |
| `affected` | ○ | `array` | 影響製品・バージョン（CVE レコードの affected） |
| `cvss` | ○ | `array` | CVSS（提供元を明記） |
| `published` | ○ | `^\d{4}-\d{2}-\d{2}$` | 公開日 |
| `updated` | ○ | `^\d{4}-\d{2}-\d{2}$` | 更新日 |
| `kev` | ○ | `object` | CISA KEV 掲載状況 |
| `service_ids` | — | `array` | 関連サービス |
| `risk_ids` | ○ | `array` | 本文（リスク評価または対応ポート）で言及しているリスク評価。ポートとの関係は製品・構成に依存 |
| `condition` | ○ | `string` | 該当条件（製品・バージョン・構成） |
| `references` | ○ | `array` | 参照 URL |
| `raw` | ○ | `^data/raw/` | 取込元の一次データ |
| `source_ids` | ○ | `array` | 根拠資料 ID（sources.source_id） |
| `verified_date` | ○ | `^\d{4}-\d{2}-\d{2}$` | 最終確認日（YYYY-MM-DD） |
| `certainty` | ○ | `["確認済み", "一部確認", "未確認"]` | 確度。確認済みには再検証済みの脅威系出典が必要 |
| `unconfirmed_notes` | ○ | `string` | 未確認事項。確認済み以外では必須（空不可） |

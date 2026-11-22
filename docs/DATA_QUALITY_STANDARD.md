# DATA_QUALITY_STANDARD — データ品質の合格基準

Port Security の品質指標は「データ件数」ではなく「**根拠を説明できるデータ件数**」とする。
すべての基準は `tools/quality.py` と `tools/validate.py` で機械検査し、CI（`validate.yml`）で 1 件でも違反があればマージ・リリースしない。

## 合格基準

| コード | 検証項目 | 合格基準 | 検査内容 |
|---|---|---|---|
| Q-JSON | JSON 構文エラー | 0 件 | リポジトリ内の全 JSON を解析 |
| Q-SCHEMA | JSON Schema 違反 | 0 件 | `data/schemas/<file>.schema.json` に対する型・必須・列挙値・形式 |
| Q-DUP | ID 重複 | 0 件 | ファイル内・ファイル間 |
| — | 参照切れ | 0 件 | `validate.py` の外部キー検査 |
| Q-ATTACK | 不正な ATT&CK ID | 0 件 | 構造化フィールドと本文の ID が公式 STIX（`data/raw/mitre/attack_catalog.json`）に実在し、revoked / deprecated でない。名称一致 |
| Q-TRANSPORT | TCP/UDP 混同 | 0 件 | 通信方式は TCP/UDP/SCTP/DCCP のいずれか。IP プロトコル番号と一致。ポート照合は必ず (番号, 通信方式) |
| Q-IPPROTO | IP プロトコル番号との混同 | 0 件 | `protocols.json` は IP プロトコル番号と階層を別フィールドで持つ |
| Q-VERIFIED | 確認済みなのに根拠なし | 0 件 | 確認済みには再検証済みの脅威系出典が必要。ポートはさらにポート固有の根拠（evidence）が必要 |
| Q-SRC | 出典の確認状態未設定 | 0 件 | `verification_status` は 確認済み / 一部確認 / 未確認。URL は https |
| Q-HIDDEN | 未確認事項の非表示 | 0 件 | 確認済み以外は未確認事項が必須。アプリ用データに確度・確認日・未確認事項を出力 |
| Q-ASSOC | 根拠のない関連付け | 0 件 | ポート→技術は関連区分と根拠を持つ |
| Q-CVE | CVE のポート直結 | 0 件 | CVE は製品・影響バージョン付きの構造化レコードとして管理し、ポート番号に直接紐付けない |
| Q-COUNT | 無断削除 | 0 件 | Phase 0 基準の ID が消えた場合は `DATA_CHANGELOG.md` に ID と理由の記載が必要 |
| Q-VIA | 確認方法の未記録・誤用（v1.2） | 0 件 | 出典は `verified_via` を持ち、確認状態は確認方法から決まる（検索結果は一部確認、原文・公式 API・公式 STIX・公式リポジトリだけが確認済み）。確認済みなら原文の所在・日付・範囲が必要 |
| Q-SCOPE | scope と内容の不一致（v1.2） | 0 件 | attack_technique は MITRE、threat_advisory / government_guidance は政府機関、tool_documentation はプロジェクト文書 等 |
| Q-ATTR | 根拠のない組織への帰属（v1.2） | 0 件 | 本文で CISA・Mirai などを挙げるなら、その組織の確認済み出典が必要 |
| Q-STAT | 出典のない統計値（v1.2） | 0 件 | 数値（%・分以内・万 IP 等）は、調査報告・政府資料の確認済み出典の確認範囲に記録されていること |
| Q-REVIEW | 根拠のない High・理由のない判定変更（v1.2） | 0 件 | Critical / High は確認済みの攻撃・脆弱性・政府・ベンダー資料か再検証の根拠が必要。判定を変えたら理由が必要 |
| Q-RISK | リスクの未分離（v1.2） | 0 件 | service_risk と exposure_condition を持ち、service_risk は根拠と判定規則（RISK_RUBRIC）に一致 |
| Q-VENDOR | ベンダーログの出典不足（v1.2） | 0 件 | 版・種別・ID・フィールド・CLI ごとにページ単位の出典。確認済みの項目は原文の抽出結果（data/raw/vendor）にあること |
| Q-LOGLINK | DET0118 専用ログの誤付与（v1.2） | 0 件 | DET0118 の analytic 専用ログは DET0118 にだけ付ける。関連付けの根拠（log_links）を持つ |
| Q-LOGCLASS | ログ分類の誤り（v1.2） | 0 件 | 分類は下の定義どおり。ポート固有ログの有無は A・B だけで判定する |
| — | 自動テスト | 全件成功 | `python3 -m unittest discover -s tools`、`flutter test` |

## 確度（certainty）の定義

| 値 | 条件 |
|---|---|
| 確認済み | 記述の中核（攻撃・検知）を、再検証済みの一次資料で確認できた |
| 一部確認 | 一部のみ一次資料で確認（例: ポート割当は IANA で確認、攻撃記述は未確認）。未確認の範囲を `unconfirmed_notes` に書く |
| 未確認 | 一次資料で確認できていない。`unconfirmed_notes` に理由を書く |

一部確認・未確認のデータは削除しない。状態を明示したまま残し、画面に表示する。

## 出典の確認状態（verification_status）

| 値 | 条件 |
|---|---|
| 確認済み | URL の内容を確認し、引用元として使う範囲（`scope`）を確認した。`access_date` 必須 |
| 一部確認 | 一部の記述のみ確認 |
| 未確認 | 存在は把握しているが内容を再確認していない |

## 出典の確認方法（verified_via、v1.2）

| 値 | 確認状態 | 意味 |
|---|---|---|
| original_document | 確認済み | 原文（ページ・PDF）を取得して内容を確認 |
| official_api / official_stix / official_repository | 確認済み | 公式の API・STIX・リポジトリの原文で確認 |
| search_result | 一部確認 | 検索結果に表示された本文でのみ確認。**原文確認として扱わない** |
| not_verified | 未確認 | 内容を確認できていない。URL が存在するだけでは主張の根拠にならない |

## 関連付けの区分（ポート → ATT&CK 技術、v1.2）

| 区分 | 意味 |
|---|---|
| direct | ポート固有の根拠（ATT&CK の説明・手順例、公式文書）が当該技術とポートを結び付けている |
| generic | どの公開サービスにも当てはまる攻撃手法（総当たり・探索・公開アプリの悪用など）を経由した関連 |
| inferred | サービス固有の攻撃手法、またはサービス（プロトコル）の性質からの推定（例: ファイル共有 → T1039、SMB → Pass-the-Hash） |
| unverified | 参考情報（一次資料未付与） |

`source_type` で根拠の種類を区別する: stix（ATT&CK 公式の記述）/ document（他の一次資料）/ curation（アプリ内の関連付け）。
ツールの技術は、ATT&CK 公式の uses 関係と、アプリ内の関連付け（攻撃手法経由）を分けて表示する。
v1.1 の区分は direct / attack_pattern / service / reference だった。

## ログの分類（v1.2）

| 分類 | 意味 | ポート固有の根拠 |
|---|---|---|
| A | 公式資料がポートを明示（port_scope=listed） | あり |
| B | DET0118 の analytic がポート番号・通信方式を示す（その analytic 専用のログ） | あり |
| B' | プラットフォーム共通（技術 → DET → analytic のプラットフォーム経由） | なし |
| C/D | 境界機器・ベンダー共通、攻撃手法・ツール経由 | 原則なし |

「ポート固有のログなし」は A・B がないことで判定する。B' は数えない。

## 優先順位

確認済みの件数を増やすことより、確認済みとした内容が正しいことを保証するのを先にする。

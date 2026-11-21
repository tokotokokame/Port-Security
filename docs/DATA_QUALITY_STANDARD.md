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

## 関連付けの区分（ポート → ATT&CK 技術）

| 区分 | 意味 |
|---|---|
| direct | ポート固有の根拠（ATT&CK 手続き例・公式文書）が当該技術とポートを結び付けている |
| service | サービス（プロトコル）の性質から当該技術の対象になる（例: ファイル共有 → T1039） |
| attack_pattern | 紐付く攻撃手法が当該技術を含む |
| reference | 参考情報（関連する可能性があるが、ポートとの結び付きは弱い） |

## 優先順位

確認済みの件数を増やすことより、確認済みとした内容が正しいことを保証するのを先にする。

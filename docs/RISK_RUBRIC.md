# RISK_RUBRIC（リスク評価の基準）

`port_risks.json` の `risk_level` は、次の基準で決めた**編集判断**です。一次資料で裏付けた値ではないため、生成したリスク評価は `certainty: 一部確認` としています（v4 から引き継いだ9件を除く）。

| レベル | 基準 | 例 |
|---|---|---|
| Critical | 外部に露出すると、未認証のまま侵入・全面的な制御・ランサムウェア被害に直結しうる | 3389/tcp、445/tcp、427/tcp、2375/tcp |
| High | 認証の突破・横展開・資格情報の窃取・制御系の操作に直結する。あるいは平文の認証がある | 22、23、135、88、1433、6379、502 |
| Medium | 偵察・情報漏えい・増幅攻撃の反射元になる。条件次第で High に上がる | 53、123、1900、80、8080、161/udp の一部 |
| Low | 単体での影響が限定的。暗号化済みの通信 | 993、995、5061、6514 |

## 判断の観点

1. 外部に露出したときの影響（インターネットから到達できるか）
2. 認証の有無と強さ（既定の認証情報・匿名アクセス・平文認証）
3. 暗号化の有無
4. 悪用時の到達点（遠隔実行・資格情報・横展開・制御系・可用性）

## v1.2: サービス固有リスクと露出条件の分離

`risk_level` は互換のため残し、次の 2 つを別に持つ（`tools/apply_v12.py` phase 4、検査は Q-RISK）。

### service_risk（一次資料で確認できた要素だけで判定）

| 要素（factors） | 判定に使う根拠 |
|---|---|
| known_exploited | このリスク評価に結び付いた CVE が CISA KEV に掲載（`vulnerabilities.kev`） |
| attack_documented | ATT&CK の記述がこのサービス・ポートを攻撃・監視の対象に挙げる（ポートの direct な根拠、ATT&CK の evidence、High 再検証の根拠） |
| government_guidance | 確認済みの政府資料・脅威勧告（scope が government_guidance / threat_advisory） |
| vendor_security_warning | 確認済みのベンダーのセキュリティ資料（scope が vendor_security） |

| level | 規則 |
|---|---|
| Critical | known_exploited かつ attack_documented かつ（government_guidance または vendor_security_warning） |
| High | known_exploited、または attack_documented かつ（government_guidance または vendor_security_warning） |
| Medium | 要素が 1 つ以上 |
| 未評価 | 要素なし。**低リスクという意味ではない**（一次資料で確認できていないだけ） |

`reason` に要素、`source_ids` に根拠、`status` に確認状態（要素があれば確認済み、なければ未確認）を記録する。
編集判断の `risk_level` と一致しなくてよい（同じ基準で判定しない）。

### exposure_condition（露出条件）

- `assumed`: `risk_level` が前提とする露出。全件 `internet`（上の観点 1「外部に露出したとき」）
- `raises`: 上げる条件（internet / untrusted_network）
- `lowers`: 下げる条件（internal_only / management_network_only / firewall_restricted / auth_access_control）

## 見直し

一次資料（ベンダーの勧告、CISA の勧告、ATT&CK の手順例など）を追加したら、`source_ids` に加えて `certainty` を見直してください。

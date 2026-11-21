# DATA_DICTIONARY（v4）

## ファイルと主キー

| ファイル | 主キー形式 | 内容 |
|---|---|---|
| `ports.json` | `PORT-{5桁}-{TCP\|UDP\|SCTP}` | ポート単位のマスター |
| `services.json` | `SRV-{略称}` | サービス辞書 |
| `protocols.json` | `PROTO-{名前}` | IPプロトコル辞書 |
| `attack_patterns.json` | `ATK-{略称}` | 攻撃手法・検知方法 |
| `port_risks.json` | `RISK-{5桁}-{通信方式}` | ポート別リスク評価 |
| `log_investigation.json` | `LOG-{基盤}-{識別子}` | ログ調査手順 |
| `mitre_techniques.json` | `T####` | ATT&CK 技術（サブ技術は `subtechniques` に内包） |
| `detection_strategies.json` | `DET####` | ATT&CK 検知戦略と analytic |
| `sources.json` | `SRC-{略称}` | 根拠資料 |

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

## log_investigation の `port_scope`

- `analytics` … 検知戦略の analytic に紐づくホストログ（Windows/Linux/ESXi/macOS）
- `any` … 境界機器ログ（FortiGate / NEC IX）。全ポート共通で適用

## sources の `scope` と `reverified_v4`

`scope`: `port_assignment` / `protocol_assignment` / `service` / `attack_technique` / `detection` / `threat_guidance` / `log_format` / `reference`

`reverified_v4`: v4 作成時に実ページを再確認したか。

## certainty の判定ルール（validate.py が強制）

| 値 | 条件 |
|---|---|
| `確認済み` | `reverified_v4=true` かつ脅威系 scope（`attack_technique` / `detection`）の資料を `source_ids` に持つ。ログは `detection` / `log_format` |
| `一部確認` | 上記を満たさない。`unconfirmed_notes` に不足を必ず記載 |
| `未確認` | 根拠なし。`unconfirmed_notes` 必須 |

DET0118 をポートの根拠に引用できるのは、DET0118 の公式監視ポート（445, 135, 3389, 5985, 5986, 1433, 3306, 427, 443, 902, 5989, 22, 5900, 8080, 8443）だけです。

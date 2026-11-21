# BASELINE_REPORT — Phase 0 現状調査（v1.1 開発開始時点）

- 対象: `main` @ `652af77`（PR #4 マージ直後）
- 調査日: 2026-11-22
- 機械可読の全結果: [`DATA_INVENTORY.json`](DATA_INVENTORY.json)（全レコード ID・ファイル一覧・参照関係・検査結果・コマンド出力）
- 再現: `python3 tools/baseline.py --v3 cyber-security-database-v3.zip`
- このフェーズではデータを変更していません（`git status` で `data/` `dist/` `app/assets/data/` に差分なしを確認）。

## 1. 調査したファイル

`DATA_INVENTORY.json` の `files` に 55 ファイル（役割・サイズ・SHA-256 先頭16桁・最終コミット日・レコード数）を記録。

| 区分 | 主なファイル |
|---|---|
| 正本データ | `data/*.json` 11 ファイル |
| 一次データ | `data/raw/iana/`（IANA CSV）、`data/raw/mitre/attack_catalog.json`（今回追加。ATT&CK v20.1 公式 STIX から生成） |
| 生成物 | `dist/{ports,kb,iana}.json` と同一内容の `app/assets/data/` |
| 文書 | `docs/`（DATA_DICTIONARY / RISK_RUBRIC / DATA_UPDATE_GUIDE / VALIDATION_REPORT / DEVELOPMENT） |
| スクリプト | `tools/`（validate / test_validate / build_index / import_mitre ほか） |
| CI | `.github/workflows/{validate,android,iana}.yml` |

ATT&CK STIX の照合元は公式 `mitre-attack/attack-stix-data` の `enterprise-attack-20.1.json` / `ics-attack-20.1.json` で、手元ファイルと公式ファイルの SHA-256 が一致することを確認済み（`539a843a…` / `3f644836…`）。v20.1 が公開中の最新版。

## 2. データ件数

| ファイル | 件数 |
|---|---|
| ports | 160（TCP 120 / UDP 40。確認済み 50 / 一部確認 110） |
| port_risks | 160（Critical 4 / High 55 / Medium 80 / Low 21） |
| services | 6 |
| protocols | 7 |
| attack_patterns | 24 |
| tools | 18 |
| log_investigation | 9 |
| mitre_techniques | 90（サブ技術 74） |
| detection_strategies | 164（analytic 533） |
| mitre_software | 11 |
| sources | 176 |

参照関係（15 種、`relations`）はすべて参照切れ 0。

### v3 元データとの対応
v3 zip は **35 ファイル**（内容の重複を除くと 20 種。例: `port_list.md` と `01_port_list.md` は同一）。計画書の「32 ファイル」とは数が異なるため、実数を記録した。

| v3 ファイル | 現在 | v3 件数 | 維持 | 欠落 | 主な変更 |
|---|---|---|---|---|---|
| ports.json | data/ports.json | 50 | 50 | 0 | `mitre_attack_ids`→`technique_ids` 改名、`source_urls` は出典 ID 参照へ統合 |
| port_risks.json | data/port_risks.json | 9 | 9 | 0 | 同上 |
| services.json | data/services.json | 6 | 6 | 0 | 同上 |
| protocols.json | data/protocols.json | 7 | 7 | 0 | 同上 |
| attack_patterns.json | data/attack_patterns.json | 7 | 7 | 0 | `target_ports` 削除（ポート側から参照） |
| log_investigation.json | data/log_investigation.json | 6 | 6 | 0 | 確度と未確認事項の訂正 |
| mitre_attack.json | mitre_techniques + detection_strategies | 3 | 3 | 0 | 技術 2 件と DET 1 件の混在を分離（`N/A` の DET は廃止） |
| sources.json | data/sources.json | 9 | 9 | 0 | なし |
| *.md 27 ファイル | docs/ | — | — | — | v4 で再構成（自動生成レポートと DATA_DICTIONARY 等に統合） |

v3 の全 ID は現行データに残っており、欠落はない。

## 3. 既存検証の実行結果（実出力）

| コマンド | 結果 |
|---|---|
| `python3 tools/validate.py data` | `825 records / errors=0 warnings=0 -> PASS` |
| `python3 -m unittest discover -s tools` | 13 件 `OK` |
| `python3 tools/build_index.py` | `assets: ports 160 / iana 11625 / techniques 164 / dets 164` |
| 生成物の差分 `git diff --stat` | なし（コミット済みの生成物と一致） |

既存の検証器は合格している。以下は **新しい品質基準（`DATA_QUALITY_STANDARD.md`）で検査した結果** で、`tools/quality.py` の出力（`DATA_INVENTORY.json` の `quality`）。

## 4. 検出したエラー（新基準）: error 92 件 / info 2 件

| コード | 件数 | 内容 |
|---|---|---|
| Q-JSON | 0 | 全 JSON の構文は正常 |
| Q-DUP | 0 | ID 重複なし |
| Q-ATTACK | 0 | 174 個の ATT&CK ID はすべて v20.1 に実在し、廃止・名称不一致なし |
| Q-SCHEMA | 1 | JSON Schema が未整備 |
| Q-TRANSPORT | 30 | サービス 6 件のポートが `'TCP / UDP'` 等の文字列。検知戦略の監視ポート 24 件が番号のみ |
| Q-IPPROTO | 7 | `protocols.json` の `transport_protocol` に「L4 Transport Protocol」等の階層説明が入り、IP プロトコル番号と通信方式が同じ欄で扱われている |
| Q-SRC | 13 | 出典の確認状態が未定義値 `未再検証`（ツール 3 件・Windows イベント 10 件） |
| Q-VERIFIED | 20 | 確認済みポート 20 件にポート固有の根拠（evidence）がない（v4 で DET0118・CISA 勧告を根拠に確認済みとしたもの） |
| Q-CVE | 6 | CVE 6 件が本文のみ。製品・影響バージョンの構造化データがない（他に `MS17-010` 表記 1 件） |
| Q-ASSOC | 10 | ポート→ATT&CK 技術の紐付けに、攻撃手法・根拠の経路がないもの |
| Q-HIDDEN | 5 | アプリ用データに攻撃手法の確度・未確認事項・確認日、ツール・ログの確認日、リスク評価の未確認事項、出典の確認状態がない |
| Q-VENDOR | 2 (info) | FortiGate / NEC IX は一部確認（Phase 4 対象。今回は記録のみ） |

## 5. 問題のある関連付け

### 5.1 ポート番号だけでログを紐付けている（TCP/UDP 混同）
- コード: `tools/build_index.py` 36 行目 `if p["port_number"] in a["monitored_ports"]:`
- 入力: `DET0118` の analytic の `monitored_ports` は番号のみ（例: AN0329 = `[427, 443, 902, 5989]`）
- 出力（`dist/ports.json`）:

| ポート | 紐付いたログ | rank | 理由 |
|---|---|---|---|
| 443/udp | LOG-ESXI-AN0329 | 0 | 「DET公式監視ポート一致」 |
| 3389/udp | LOG-WIN-AN0327 / LOG-WIN-SECURITY | 0 | 「DET公式監視ポート一致」 |
| 443/udp・2049/udp | LOG-LIN-AN0328 | 2 | 「DETサービス名から推定」 |

DET の記述は番号のみで通信方式を明記していないため、UDP レコードに「公式一致（最上位）」を付けるのは根拠を超えた表示。

### 5.2 ポート→ATT&CK 技術の直接紐付け（根拠経路なし）10 件

| ポート | 技術 | ポートの攻撃手法 |
|---|---|---|
| 69/tcp, 69/udp | T1552.001 | ATK-CRED-THEFT（T1552.001 を含まない） |
| 548/tcp, 873/tcp, 2049/tcp, 2049/udp | T1039 | ATK-BRUTE-FORCE 等 |
| 593/tcp | T1046 | ATK-REMOTE-EXPLOIT, ATK-AD-RECON |
| 2179/tcp | T1021 | ATK-HYPERVISOR |
| 2483/tcp | T1078.001 | ATK-BRUTE-FORCE |
| 3283/tcp | T1021.005 | ATK-BRUTE-FORCE, ATK-EXTERNAL-REMOTE |

技術自体は妥当でも、画面上で「なぜこの技術か」を示せない。

### 5.3 サービスとポートの対応
`services.json` は 1 サービス = 1 ポート番号 + `'TCP / UDP'` の文字列で、`port_number` は 1 つだけ。53/tcp と 53/udp のような通信方式別の対応を表現できない。

## 6. 根拠資料の不足
- 出典の確認状態 `未再検証` 13 件（SRC-HYDRA / SRC-NMAP / SRC-SAMBA-SMBCLIENT / SRC-MS-EVT-4624 ほか）
- 確認済みポート 20 件にポート固有の根拠なし（17/udp, 19/udp, 22/tcp, 111/udp, 135/tcp, 427/tcp, 445/tcp, 520/udp, 902/tcp, 1433/tcp, 1900/udp, 3306/tcp, 3389/tcp, 4444/tcp, 5353/udp, 5900/tcp, 5985/tcp, 5986/tcp, 5989/tcp, 11211/udp）
- CVE: CVE-2019-0708, CVE-2022-21893, CVE-2020-0796, CVE-2024-6387, CVE-2021-21974, CVE-2023-46604（+ MS17-010）に影響製品・バージョン・CVSS・KEV の構造化データなし

## 7. 修正が必要なコード
| ファイル | 内容 |
|---|---|
| `tools/build_index.py` | 監視ポートを (番号, 通信方式) で照合する。技術ごとに関連区分を出力する。攻撃手法・ツール・ログ・リスクの確度/未確認事項/確認日を出力する |
| `tools/validate.py` | スキーマ・通信方式・出典状態・ATT&CK 実在・CVE・件数差分の検査を合格条件に組み込む |
| `tools/import_mitre.py` | 監視ポートを通信方式付きで出力する |
| `app/lib` | 攻撃手法・ツール・ログ・リスクの確度・確認日・未確認事項、技術の関連根拠、CVE（製品・バージョン条件付き）を表示する |

## 8. 修正が必要なデータ
| ファイル | 内容 |
|---|---|
| `detection_strategies.json` | 監視ポートを `[番号, 通信方式]` へ |
| `services.json` | `ports: [[番号, 通信方式], …]` へ（旧フィールドは互換のため維持） |
| `protocols.json` | IP プロトコル番号と階層を別フィールドに |
| `sources.json` | `未再検証` を定義済みの状態へ（再確認できたものは確認済み、それ以外は未確認） |
| `ports.json` | 確認済み 20 件に根拠（evidence）を付与、技術の関連区分を付与 |
| 新規 `vulnerabilities.json` | CVE を製品・影響バージョン経由で管理（公式 CVE レコードと CISA KEV から生成） |

## 9. 既存仕様との互換性
- ID 体系（`PORT-00445-TCP` 等）は変更しない。
- 既存フィールドは削除せず、追加フィールドで表現する（例: `services.port_number` は残し `ports` を追加）。
- アプリは JSON の欠損に寛容な読込み（`json.dart`）のため、生成物にフィールドを追加しても旧バージョンのアプリは動作する。
- ファイル配置（計画書 4 章のディレクトリ再編）は今回は行わない。移行試験を経てから採用する。

## 10. Phase 1 に進むための条件
- [x] 現データの全 ID・件数・ハッシュを `DATA_INVENTORY.json` に保存（以後の無断削除を CI で検出できる）
- [x] 既存検証がすべて合格していることを確認
- [x] 新基準の検査器（`tools/quality.py`）で現状の違反を一覧化
- [x] 元に戻せること: 基準コミット `652af77` と `DATA_INVENTORY.json` の SHA-256 で照合可能

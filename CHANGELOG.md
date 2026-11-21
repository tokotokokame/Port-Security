# CHANGELOG

## v5 / app v2.0 (2026-11-21)

### データ
- IANA 公式台帳（11,625 ポート）を基本レイヤーとして収録しました。取得は CI の `refresh-iana` で行います。
- 詳細付きポートを51件から160件に増やし、全件にリスク評価を付けました（基準は `docs/RISK_RUBRIC.md`）。
- 攻撃手法を7件から24件に増やしました（Kerberoasting、名前解決ポイズニング、DCSync、反射型DDoS、コンテナ API の悪用など）。
- 攻撃ツール18件を追加しました（Impacket、Mimikatz、CrackMapExec、Responder、Rubeus、BloodHound、smbclient など）。記載は検知の痕跡だけで、SigmaHQ のルールと各公式文書で裏取りしています。
- ログ調査に Hyper-V、VirtualBox、Windows Security を追加しました。
- ATT&CK v20.1 の公式 STIX から、技術90件（サブ技術74件）、検知戦略164件、analytic 533件を取り込みました。

### アプリ
- ターミナル風の UI に作り直しました（ダーク固定、等幅フォント）。
- 検索バーの下に「詳細検索設定」を追加し、例示用の選択チップを削除しました。
- 下部タブを `ports / attacks / tools / logs` にしました。
- アプリアイコンをドット絵（シールド＋ポート）にしました（アダプティブアイコン対応）。

## app v1.0 (2026-11-21)

- Android アプリ（Flutter）を追加しました。`port_index.json` を同梱したオフライン検索です。
- CI で analyze・test・APK ビルド・APK のセキュリティ点検を行い、`main` に入るたびに Releases へ APK を公開します。

## v4.0.0 (2026-11-21)

v3 の監査で、ポートから攻撃手法・出典までは辿れる一方、MITRE詳細・ログ調査・リスク評価でリンクが途切れていることが判明しました。v4 はその修正版です。変更の詳細は `tools/migrate_v3_to_v4.py` に残しています。

### リンク構造
- ports に `service_id` / `risk_id` / `protocol_id` を追加しました。
- attack_patterns と検知戦略の analytic に `log_investigation_ids` を追加し、ログ調査へIDで到達できるようにしました（v3はIDリンクが0件）。
- log_investigation に `analytics_ids` / `port_scope` を追加しました。
- attack_patterns の `target_ports` を廃止しました（ports 側と最大9件ずれていたため、両方向の和集合を ports に統合）。
- `source_urls` を廃止し、URL は sources.json に一本化しました。

### MITRE ATT&CK（attack.mitre.org で再確認）
- `mitre_attack.json` を `mitre_techniques.json`（12技術）と `detection_strategies.json`（11戦略）に分割しました。参照される技術ID はすべて収録しています（v3は49件が未収録）。
- `DET0118` を technique ID 欄から除き、検知戦略として分離しました。
- 架空の analytic ID（`AN-T1110-001` など）を削除し、公式の DET0463（T1110）と DET0269（T1021）に置き換えました。
- T1110 の version / created を公式値（2.8 / 2017-05-31）に修正しました（v3は 14.1 / 2020-02-11）。
- T1003（OS Credential Dumping）の誤用を修正しました。平文盗聴は T1040、Kerberoasting は T1558.003/.004、NBT-NS ポイズニングは T1557.001、TFTP の設定ファイル取得は T1552.001、IKE PSK・MS-CHAPv2 は T1110.002 / T1557 に変更しています。
- サブ技術を精緻化しました（VNC → T1021.005、WinRM → T1021.006）。
- DET0118/AN0328（Linux）は公式ページにポート番号がないため、`port_basis: inferred` と明記しました。

### データ
- `PORT-00427-TCP`（svrloc / OpenSLP）を新設し、port_risks の孤立レコードを解消しました。
- certainty を根拠に基づいて再判定しました。脅威系の一次資料がないレコードは「一部確認」にし、不足を `unconfirmed_notes` に記載しています（ports: 確認済み 9 / 一部確認 42）。
- 根拠に引ける DET0118 を、公式の監視ポートに限定しました。

### ツール・ドキュメント
- `tools/validate.py`（参照整合性・双方向リンク・certainty 根拠ルール）と、その自己テストを追加しました。
- `tools/build_index.py` で `dist/port_index.json`（ポート単位の結合済みデータ、ログの関連度付き）と `docs/VALIDATION_REPORT.md` を自動生成するようにしました。
- GitHub Actions で検証と生成物の差分チェックを行うようにしました。
- v3 で重複していた Markdown（同一内容が2〜5部）を `docs/` の3ファイルに統合しました。

---

## v3 以前の履歴（v3 同梱の CHANGELOG をそのまま収録）


### 概要
本データベースは「サイバー攻撃ポート・プロトコルデータベース 修正版作成指示書 v2.0」に基づき、原本の32ファイルをすべて保全した上で、データ整合性の検証・修正および新規レコード追加を行いました。

### 主な変更点と修正内容

### 1. ID参照の完全修復 (ID Integrity Restoration)
- **問題点**: 以前のバージョンにおいて `ATK-CRED-THEFT` および `ATK-DATA-EXFIL` への参照切れが存在していた。
- **修正内容**:
  - `attack_patterns.json` に `ATK-CRED-THEFT` (資格情報盗聴・メモリダンプ) および `ATK-DATA-EXFIL` (データ流出・C2トンネリング) のレコードを新規定義。
  - `ports.json` および `services.json` 内の該当参照を完全接続。参照切れ数を **0件** に改善。

### 2. MITRE ATT&CK マッピングの公式準拠修正 (MITRE ATT&CK Alignment)
- **問題点**: ブルートフォース攻撃に誤って `T1210` が割り当てられていた。
- **修正内容**:
  - ブルートフォース系攻撃を **`T1110`** (Brute Force) および Sub-technique **`T1110.001`** (Password Guessing), **`T1110.003`** (Password Spraying) へ修正。
  - **`T1210`** をリモートサービスの未修正脆弱性悪用 (Exploitation of Remote Services) として厳格に再定義。
  - **`T1021.001`** (RDP), **`T1021.002`** (SMB), **`T1021.004`** (SSH) を正しく分類。

### 3. ポートレコードの大幅拡充とTCP/UDP完全分離 (Port Dataset Expansion)
- **問題点**: 既存のポート数が14件と不足しており、同一ポート番号のTCP/UDP区別が一部不十分であった。
- **修正内容**:
  - 主要セキュリティポート (FTP 20/21, SSH 22, Telnet 23, SMTP 25, DNS 53, DHCP 67/68, TFTP 69, HTTP 80, Kerberos 88, POP3 110, NTP 123, MS-RPC 135, NetBIOS 137-139, IMAP 143, SNMP 161/162, LDAP 389, HTTPS 443, HTTP/3 443 UDP, SMB 445, Syslog 514, OpenVPN 1194, MSSQL 1433, Oracle 1521, L2TP 1701, PPTP 1723, MySQL 3306, RDP 3389, IPsec 4500/500, PostgreSQL 5432, VNC 5900, WinRM 5985/5986 等) を全網羅。
  - レコード数を **50件** に拡大。全件において `PORT-03389-TCP` と `PORT-03389-UDP`、`PORT-00443-TCP` (HTTPS) と `PORT-00443-UDP` (HTTP/3 QUIC) のように通信方式ごとに別IDとして完全分離。

### 4. IPプロトコル番号とトランスポートポートの分離 (IP Protocol Numbers)
- ICMP (Protocol 1), GRE (Protocol 47), ESP (Protocol 50), AH (Protocol 51) をL4ポート番号ではなく、IP Protocol Number として `protocols.json` 内で明確に区分。

### 5. リスク評価スケールの標準化 (Risk Assessment 4-Level Standard)
- リスク評価レベルを **Critical / High / Medium / Low** の4段階に統一し、外部公開性・認証・暗号化・脆弱性存在の定量的評価軸を紐付け。

### 6. ベンダー機器ログフィールドの根拠強化 (FortiGate & NEC IX)
- FortiGate (FortiOS 7.x) および NEC UNIVERGE IX シリーズの公式ドキュメントに基づき、ログフィールド名 (`srcip`, `dstip`, `action`, `ident=FLT`, `filter-id`等) を記録。実在確認未完了オプションは「一部確認/未確認」と明確化。

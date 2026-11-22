# DATA_CHANGELOG — データ変更履歴

データ（`data/`）の追加・変更・削除をレコード単位で記録する。
Phase 0 基準（`docs/baseline/DATA_INVENTORY.json`）にある ID を削除・改名する場合は、**その ID と理由をここに書かないと CI が失敗する**（Q-COUNT）。

## v1.2（2026-11-22）

### Phase 1（出典・帰属・High 再検証）— `tools/apply_v12.py` phase 1
**出典の確認方法（F-12）**
- `sources` に `verified_via`（original_document / official_api / official_stix / official_repository / search_result / not_verified）・`verified_url`・`verified_date`・`verified_by`（manual_review / automated_import）・`verified_notes` を追加。v1.1 まで `verified_via` に入れていた URL は `verified_url` へ移した。
- 確認状態は確認方法から決める: 原文・公式 API・公式 STIX・公式リポジトリ → 確認済み、検索結果 → 一部確認、未確認 → 未確認（Q-VIA）。
- 確認状態が変わった出典:
  - SRC-CISA-AMP（TA14-017A）・SRC-CISA-TA18-106A: 確認済み → 一部確認。原文ページを取得できず、検索結果に表示された本文でのみ確認。
  - SRC-MS-HYPERV-EVTLOG・SRC-NVD-CVE-2023-46604: 確認済み → 未確認。本文を取得できなかった（NVD の主張は SRC-CVE-2023-46604 と SRC-CISA-KEV で確認済み）。
  - SRC-FORTINET-DOCS・SRC-NEC-IX: 一部確認 → 未確認。サイトのトップページで、特定の資料を指していない（Phase 2 で置き換え）。
- Sigma ルール 16 件: SigmaHQ の原文を取得し、ルールが存在して title が一致することを確認。

**scope の再分類（F-11）** — 内容を確認したうえで個別に移した（一括置換はしていない）
- tool_documentation: KERBRUTE, CHISEL, EVILWINRM, HYDRA, NMAP, SAMBA-SMBCLIENT, METASPLOIT-REVSHELL
- vendor_security: DOCKER-REMOTE, DOCKER-PROTECT, REDIS-SECURITY, MONGODB-CHECKLIST, K8S-KUBELET, ETCD-SECURITY, APACHE-CVE-2023-46604, CISCO-TSA18-106A
- research_report: REDIS-ANTIREZ, PANW-XPANSE-2021（新規）／ vulnerability_database: NVD-CVE-2023-46604 ／ government_guidance: CISA-HYGIENE ／ attack_framework: MITRE-ATTACK
- MITRE ATT&CK for ICS の 9 件（T0836, T0869, T0806, T0888, T0846-001, T0883, T0885, T0846-002, T0871）: threat_advisory → attack_technique（脅威勧告ではなく攻撃技術の解説）
- 確認済みの条件（攻撃手法・検知・脅威勧告の再検証済み資料）は変えていない。ベンダー資料・ツール資料・調査報告だけを根拠にしていた次のレコードを 確認済み → 一部確認 に変更（理由は各レコードの未確認事項に記載）:
  - PORT-00017-UDP, PORT-00019-UDP, PORT-00111-UDP, PORT-00520-UDP, PORT-01900-UDP, PORT-05353-UDP, PORT-11211-UDP（根拠の SRC-CISA-AMP が一部確認になったため）
  - PORT-02379-TCP, PORT-06379-TCP（etcd・Redis の公式資料はベンダー資料）
  - TOOL-METASPLOIT, TOOL-KERBRUTE（ツール資料）
- PORT-04444-TCP は ATT&CK T1571 の手順例（C0032・DarkVishnya が 4444 を C2 に使用）を根拠に追加し、確認済みを維持。

**出典の統合・未使用・空欄（F-19〜F-21）**
- SRC-MS-SVC-PORTS を SRC-MS-PORTS（同一 URL）に統合。参照は SRC-MS-PORTS へ移し、旧 ID は `merged_into` を付けて残した（usage_status=廃止）。
- `usage_status` を追加（使用中 188 / 未使用・再確認待ち 3 / 廃止 1）。未使用の SRC-MITRE-DET0314・SRC-MITRE-DET0348・SRC-MITRE-ICS-T0885 は削除せず、理由を `usage_notes` に記載。
- 空欄だった `notes` は確認した範囲（`verified_notes`）で埋めた。推測による補記はしていない。

**本文の帰属（F-01〜F-03）**
- ATK-VULN-SCAN「CISA分析によればCVE公表後15分以内に無差別探索スキャンが発生」: CISA の資料には見つからなかった。数値の出典は Palo Alto Networks（Cortex Xpanse、2021-05-19）で、内容は「2021年1〜3月、50 社・5,000 万 IP の観測で、探索スキャンの多くは CVE 公表から 15〜60 分後（Exchange は 5 分以内）」。本文と出典（SRC-PANW-XPANSE-2021）をこれに合わせた。
- SRC-CISA-HYGIENE（Summit 2022 PDF）: 原文の「Exposed Vulnerable Services」に RDP が含まれていた。**v1.1 で PORT-03389-TCP から出典を外したのは検索結果の誤読**による誤りのため、出典を戻した。SSH は露出サービスの一覧になく暗号の文脈のみのため、RISK-00022-TCP から外した。PORT-00389-UDP に出典を追加。
- 出典を特定できない帰属を、原文の記述に置き換え:
  - 「CISA Bad Practice」（RISK-03389-TCP, RISK-00023-TCP, PORT-00138-UDP）、「CISA緊急勧告」（RISK-00445-TCP, PORT-00445-TCP）、「CISA最優先遮断勧告」（RISK-00445-TCP）、「CISA要請」（PORT-00389-UDP）→ SRC-CISA-HYGIENE の記載（「インターネットに公開すべきでない」等）
  - 「Mirai」（PORT-00023-TCP, RISK-00023-TCP）: 一次資料を確認できなかったため名称を削除。RISK-00023-TCP は ATT&CK T1110.001 の記載に置き換え
- PORT-61616-TCP「CISA KEV 掲載」の根拠を NVD から SRC-CISA-KEV に変更。ATK-REMOTE-EXPLOIT に SRC-CISA-KEV を追加。

**攻撃手法の確度分離（F-08・F-09）**
- `attack_mapping_status`（ATT&CK 技術への対応付け。公式 STIX と照合）・`content_verification_status`（本文）・`content_source_ids` を追加。対応付けは 24 件とも確認済み、本文は 24 件とも一部確認（逐条照合が未実施）。互換用の `certainty` は弱い方に合わせて 一部確認。
- `unconfirmed_notes` に入っていた変更履歴を削除し、ここに移した（原文のまま）:
  - ATK-BRUTE-FORCE: T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying) に正しく分類。
  - ATK-REMOTE-EXPLOIT: T1210 (Exploitation of Remote Services) および DET0118 アナリティクスと完全合致。
  - ATK-LATERAL-MOVE: Sub-technique T1021.001(RDP), T1021.002(SMB), T1021.004(SSH) を明記。
  - ATK-CRED-THEFT: 欠損していた参照ID `ATK-CRED-THEFT` を正式定義。
  - ATK-DATA-EXFIL: 欠損していた参照ID `ATK-DATA-EXFIL` を正式定義。
  - ATK-VULN-SCAN: T1595 (Active Scanning) および T1595.002 (Vulnerability Scanning) に対応。
  - ATK-RANSOMWARE: T1486 (Data Encrypted for Impact) を割り当て。

**High 27 件の再検証（F-13）** — 確認観点: 用途・露出リスク・既知の脆弱性と悪用・認証と暗号・攻撃との関係・ログ・一次資料。IANA は割当の根拠のみで、リスクの根拠にしない。結果は各レコードの `review` に記録。
- High を維持（12）: 21, 23, 102, 389, 3283, 5432, 5984, 6443, 9200, 20000, 27017, 44818/tcp。根拠は ATT&CK（T1110.001 の主な対象一覧、T0846 の手順例、T0869、T0871 など）と KEV。
  - KEV 掲載 CVE を追加: CVE-2022-24706（CouchDB）、CVE-2015-1427・CVE-2014-3120（Elasticsearch）、CVE-2025-14847（MongoDB Server）。cvelistV5・kev-data から取込。
  - PORT-00021-TCP・PORT-00023-TCP・PORT-00389-TCP に T1110.001（説明でサービスとポートを列挙）を直接の根拠として追加。
- Medium に変更（15）: 512, 513, 873, 1521, 1723, 2049, 2179, 3260, 6000, 6600, 7547, 11211, 18083/tcp、3389/udp、47808/udp。ATT&CK・KEV・政府勧告で悪用や攻撃対象としての記載を確認できなかった。
- 27 件以外で根拠を失った High 2 件を同じ基準で再検証し維持: RISK-11211-UDP（T1498.002 で memcache の増幅を記載。ポート番号の記載はない）、RISK-04444-TCP（T1571 の手順例）。
- リスク分布: Critical 4 / High 55 → 40 / Medium 80 → 95 / Low 21。

## v1.1（2026-11-22）

### Phase 0
- 基準スナップショットを作成（`main` @ `652af77`、825 レコード）。データの変更なし。
- `data/raw/mitre/attack_catalog.json` を追加（ATT&CK v20.1 公式 STIX から ID・名称・廃止状態を抽出）。

### Phase 1（根拠管理）— `tools/apply_v11.py` phase1
- 出典の確認状態 `未再検証` 13 件を一次資料で確認し `確認済み` に。確認に使った資料を `verified_via` に記録。
  - SRC-HYDRA / SRC-NMAP / SRC-SAMBA-SMBCLIENT: 公式リポジトリの README・man page（smbclient は既定 139/tcp のみ記載、445/tcp は記載なし → TOOL-SMBCLIENT の未確認事項に明記）
  - SRC-MS-EVT-4624/4625/4648/4662/4697/4768/4771/4776/5140/5145: Microsoft Learn の各イベントページで名称を確認
- v3 から継承した `確認済み`（再確認記録なし）を再確認:
  - SRC-MS-RDS: 公式ソース（MicrosoftDocs/SupportArticles-docs）で掲載ポートを確認。**UDP 88 と TCP 5986 は記載なし** → PORT-00088-UDP / PORT-05986-TCP の出典を新規 SRC-MS-SVC-PORTS（同社「Service overview and network port requirements」、両ポートを記載）へ付け替え
  - SRC-CISA-HYGIENE: タイトル（Summit 2022 PDF）と URL（サービス紹介ページ）が別資料を指していたため、本文を確認できた PDF の URL に修正。本文の対象は SMB / NetBIOS / Kerberos / LDAP / Telnet で **RDP は記載なし** → PORT-03389-TCP から出典を外した
  - SRC-IETF-RFC: タイトルから無関係な「/ RFC 8126」を削除（URL は RFC 6335）
  - SRC-MITRE-ATTACK: 公式 STIX v20.1 で確認
  - SRC-IANA-PROTO: IANA Protocol Numbers CSV（iana.yml で取得）と照合する検査を追加
- 確認済みポート 20 件にポート固有の根拠（evidence）を付与:
  - DET0118 の analytic（AN0327 の ServicePortSet、AN0329 の NSM:Flow、AN0330 の ServicePortSet）: 22, 135, 427, 445, 902, 1433, 3306, 3389, 5900, 5985, 5986, 5989/tcp
  - CISA TA14-017A の Systems Affected: 17, 19, 111, 520, 1900, 5353, 11211/udp
  - Metasploit 公式ドキュメントのリバースシェル例（LPORT=4444。フレームワークの既定値ではない）: 4444/tcp

### Phase 2（通信方式）— `tools/apply_v11.py` phase2 / `tools/import_mitre.py`
- detection_strategies: DET0118 の監視ポートを `[番号, 通信方式]` に変更し、`transport_basis`（stated / service_default / none）を追加。AN0329 は公式に `tcp/427` 等と明記、AN0327・AN0330・AN0328 はサービスの標準通信方式（TCP）
  - 結果: 443/udp・3389/udp・2049/udp に付いていた「DET公式監視ポート一致」「DETサービス名から推定」の紐付けを解除
- services: `ports: [[番号, 通信方式], …]` を追加（参照元ポートから導出）。旧 `port_number` / `transport_protocol` / `protocol_number` は互換のため残す（非推奨）
- protocols: `ip_protocol_number` / `layer` / `has_port_numbers` を追加し、IP プロトコル番号と通信方式を分離
- ports / port_risks: service_name を IANA 登録名に統一（慣用名は formal_name に残す）
  - 443/udp http-3→https、514/tcp syslog-conn→shell（syslog-conn は 601/tcp）、5900/tcp vnc→rfb、6000/tcp (未登録)→x11、6667/tcp (未登録)→ircu、8443/tcp https-alt→pcsync-https
  - 同じ番号に複数の登録がある 4 件をレコード内容に合う登録名へ: 465/tcp urd→submissions、1701/udp l2f→l2tp、2049/tcp・udp shilp→nfs
  - iana_description は IANA CSV の記載をそのまま使用（6000/tcp・6667/tcp は空欄だったものを補完）
- protocols: IANA Protocol Numbers 台帳（CI で取得、`data/raw/iana/protocol-numbers-1.csv`）と 7 件の番号・キーワードが一致することを確認

### Phase 1（スキーマ）
- `data/schemas/*.schema.json`（12 ファイル、JSON Schema 2020-12）と `docs/DATA_SCHEMA_SPEC.md` を `tools/make_schemas.py` で生成。全レコードがスキーマに適合

### Phase 3（ATT&CK 関連付け）— `tools/apply_v11.py` phase3
- ports に `technique_basis`（技術ごとの関連区分 direct / attack_pattern / service / reference と経路）を追加。271 件中 direct 57 / attack_pattern 204 / service 5 / reference 5
- 経路がなかった 10 件は内容を確認し、ファイル共有系の T1039（548・873・2049）と VMConnect の T1021（2179）を service、残り 5 件を reference（一次資料未付与と明記）に分類
- ATT&CK v20.1 公式 STIX との照合: 存在しない・廃止・名称不一致 0 件（`docs/MITRE_VALIDATION_REPORT.md`）

### Phase 5（CVE）— `tools/fetch_cve.py` / `tools/import_cve.py` / `tools/cve_catalog.py`
- 新規 `data/vulnerabilities.json`（7 件）: CVE-2017-0144 / CVE-2019-0708 / CVE-2020-0796 / CVE-2021-21974 / CVE-2022-21893 / CVE-2023-46604 / CVE-2024-6387
  - 題名・説明・影響製品・影響バージョン・修正版（lessThan / unaffected）・CVSS（提供元つき）・公開日・更新日は CVE Program の公式レコード（CVEProject/cvelistV5）から、KEV 掲載状況は CISA 公式 kev-data（catalog 2026.11.20）からそのまま取り込み。原文は `data/raw/cve/`・`data/raw/kev/`
  - CVSS は CNA（microsoft / apache / redhat）、CNA にない旧 CVE は CISA-ADP の値。提供元を併記
  - KEV: 0144 / 0708 / 0796 / 46604 は掲載、21974 / 21893 / 6387 は未掲載（全 1,790 件で確認）
  - ポート番号には直接紐付けず、`condition`（製品・バージョン・構成）と `risk_ids`（本文で言及しているリスク評価）で管理
- RISK-00445-TCP: 「MS17-010 (EternalBlue)」に CVE-2017-0144 を併記（EternalBlue = CVE-2017-0144 は ATT&CK の手続き例 S0260 による）
- sources: SRC-CVE-* 7 件と SRC-CISA-KEV を追加（scope: vulnerability）

### Phase 6（自動検証）
- データの変更なし。CI の品質ゲート・注入テスト・週次の鮮度チェックを追加（`docs/TEST_REPORT.md`）

### Phase 4（FortiGate / NEC IX）
- 今回は対象外。LOG-FORTIGATE-VENDOR / LOG-NECIX-VENDOR は `一部確認` のまま（quality.py が info として記録）

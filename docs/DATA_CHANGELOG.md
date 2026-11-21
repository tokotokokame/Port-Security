# DATA_CHANGELOG — データ変更履歴

データ（`data/`）の追加・変更・削除をレコード単位で記録する。
Phase 0 基準（`docs/baseline/DATA_INVENTORY.json`）にある ID を削除・改名する場合は、**その ID と理由をここに書かないと CI が失敗する**（Q-COUNT）。

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

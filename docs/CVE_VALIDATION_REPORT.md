# CVE_VALIDATION_REPORT（自動生成: tools/build_index.py）

- 取込元: CVE Program 公式レコード（CVEProject/cvelistV5）と CISA KEV（cisagov/kev-data）。`data/raw/cve/` に原文を保存
- CVE はポート番号に直接紐付けない。製品・影響バージョン・構成を `condition` に明記し、リスク評価から参照する
- 収録: 11 件 / 検査の違反: **0 件**

| CVE | 製品 | 影響バージョン | 修正 | CVSS | KEV | 該当条件 |
|---|---|---|---|---|---|---|
| CVE-2014-3120 | （CNA 記載なし） n/a | n/a | — | 8.1 (v3.1, CISA-ADP) | 掲載 2022-03-25 | 動的スクリプトが有効な既定設定の Elasticsearch 1.2 より前（CVE レコードの説明による） |
| CVE-2015-1427 | （CNA 記載なし） n/a | n/a | — | 9.8 (v3.1, CISA-ADP) | 掲載 2022-03-25 | Groovy スクリプトが有効な Elasticsearch 1.3.8 より前・1.4.x の 1.4.3 より前（CVE レコードの説明による）。9200/tcp の IANA 登録名は wap-wsp で、Elasticsearch の利用は慣用 |
| CVE-2017-0144 | Microsoft Corporation Windows SMB | The SMBv1 server in Microsoft Windows Vista SP2; Windows Server 2008 SP2 and R2 SP1; Windows 7 SP1; Windows 8.1; Windows Server 2012 Gold and R2; Windows RT 8.1 | — | 8.8 (v3.1, CISA-ADP) | 掲載 2022-02-10 | 記載の Windows の SMBv1 サーバ（細工したパケットで任意コード実行）。445/tcp が開いているだけでは該当しない |
| CVE-2019-0708 | Microsoft Windows; Microsoft Windows Server | 7 for 32-bit Systems Service Pack 1; 7 for x64-based Systems Service Pack 1 | — | 9.8 (v3.1, CISA-ADP) | 掲載 2021-11-03 | 影響バージョンの Windows の Remote Desktop Services に、未認証の攻撃者が RDP で接続した場合（affected を参照） |
| CVE-2020-0796 | Microsoft Windows 10 Version 1903 for 32-bit Systems; Microsoft Windows 10 Version 1903 for x64-based Systems（ほか 6 件） | unspecified | — | 10 (v3.1, CISA-ADP) | 掲載 2022-02-10 | SMB 3.1.1 を処理する Windows 10 / Windows Server のバージョン 1903・1909（affected を参照） |
| CVE-2021-21974 | （CNA 記載なし） VMware ESXi; （CNA 記載なし） VMware Cloud Foundation | 7.0 before ESXi70U1c-17325551; 6.7 before ESXi670-202102401-SG（ほか 1 件） | — | 8.8 (v3.1, CISA-ADP) | 未掲載 | OpenSLP を使う影響バージョンの VMware ESXi に、同一ネットワークセグメントから 427 へ到達できる場合（affected を参照） |
| CVE-2022-21893 | Microsoft Windows 10 Version 1809; Microsoft Windows Server 2019（ほか 21 件） | 10.0.17763.0 < 10.0.17763.2452; 10.0.0 < 10.0.17763.2452 | 10.0.10240.19177; 10.0.14393.4886; 10.0.17763.2452（ほか 9 件） | 8 (v3.1, microsoft) | 未掲載 | 影響バージョンの Windows で Remote Desktop Protocol を利用している場合（affected を参照） |
| CVE-2022-24706 | Apache Software Foundation Apache CouchDB | Apache CouchDB ≤ 3.2.1 | — | 9.8 (v3.1, CISA-ADP) | 掲載 2022-08-25 | Apache CouchDB 3.2.2 より前で、既定の設定のまま適切に保護されていないインストール（affected を参照）。ポート番号だけでは判定できない |
| CVE-2023-46604 | Apache Software Foundation Apache ActiveMQ; Apache Software Foundation Apache ActiveMQ Legacy OpenWire Module | 5.18.0 < 5.18.3; 5.17.0 < 5.17.6（ほか 2 件） | 5.15.16; 5.16.7; 5.17.6（ほか 1 件） | 10 (v3.1, apache) | 掲載 2023-11-02 | 影響バージョンの Apache ActiveMQ の Java OpenWire ブローカー・クライアント。ポート番号だけでは判定できない |
| CVE-2024-6387 | https://www.openssh.com/ OpenSSH; Red Hat Red Hat Enterprise Linux 9（ほか 7 件） | 8.5p1 ≤ 9.7p1 | 0:8.7p1-12.el9_0.1; 0:8.7p1-30.el9_2.4; 0:8.7p1-38.el9_4.1（ほか 4 件） | 8.1 (v3.1, redhat) | 未掲載 | 影響バージョンの OpenSSH サーバ（sshd）。ディストリビューションの修正状況は各ベンダー情報を確認 |
| CVE-2025-14847 | MongoDB Inc. MongoDB Server | 8.2 < 8.2.3; 8.0 < 8.0.17（ほか 7 件） | 4.4.30; 5.0.32; 6.0.27（ほか 3 件） | 8.7 (v4.0, mongodb); 7.5 (v3.1, mongodb) | 掲載 2025-12-29 | Zlib 圧縮を使う影響バージョンの MongoDB Server（未認証のクライアントがヒープの未初期化領域を読み取りうる。affected を参照） |

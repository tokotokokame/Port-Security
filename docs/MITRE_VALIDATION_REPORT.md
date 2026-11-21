# MITRE_VALIDATION_REPORT（自動生成: tools/build_index.py）

- 照合元: ATT&CK v20.1 公式 STIX（`data/raw/mitre/attack_catalog.json`）
  - Enterprise ATT&CK v20.1 sha256 `539a843a7b53ed97…`
  - ICS ATT&CK v20.1 sha256 `3f6448369f9135ad…`
- 照合した技術 ID: 構造化フィールド 164 個（本文中の ID も含めて検査）
- 存在しない / 廃止（revoked・deprecated）/ 名称不一致: **0 件**

## 重点確認対象

| ID | 公式名 | 状態 | 本データの名称 | 紐付くポート（関連区分） |
|---|---|---|---|---|
| T1110 | Brute Force | 有効 | Brute Force | attack_pattern 44 |
| T1110.001 | Password Guessing | 有効 | Password Guessing | — |
| T1110.002 | Password Cracking | 有効 | Password Cracking | attack_pattern 2 |
| T1110.003 | Password Spraying | 有効 | Password Spraying | — |
| T1110.004 | Credential Stuffing | 有効 | （未収録） | — |
| T1021.001 | Remote Desktop Protocol | 有効 | Remote Desktop Protocol | attack_pattern 1 |
| T1021.002 | SMB/Windows Admin Shares | 有効 | SMB/Windows Admin Shares | attack_pattern 1, direct 1 |
| T1021.004 | SSH | 有効 | SSH | attack_pattern 1 |
| T1046 | Network Service Discovery | 有効 | Network Service Discovery | attack_pattern 14, reference 1 |
| T1210 | Exploitation of Remote Services | 有効 | Exploitation of Remote Services | attack_pattern 9, direct 13 |

## ポート → 技術の関連区分

ATT&CK の技術とポート番号は直接結び付けず、経路（Port → 根拠 / 攻撃手法 / サービス → Technique）を持たせる。

| 区分 | 件数 | 意味 |
|---|---|---|
| direct | 57 | ポート固有の根拠（ATT&CK 手続き例・検知戦略・公式文書）が技術を名指し |
| attack_pattern | 204 | 紐付く攻撃手法がその技術（または親・サブ技術）を含む |
| service | 5 | サービスの性質から対象になる |
| reference | 5 | 参考情報（一次資料未付与） |

### service / reference の内訳

| ポート | 技術 | 区分 | 説明 |
|---|---|---|---|
| 69/TCP | T1552.001 | reference | TFTP は認証なしで設定ファイルを取得できるため、ファイル内の資格情報が狙われうる（一次資料未付与） |
| 69/UDP | T1552.001 | reference | TFTP は認証なしで設定ファイルを取得できるため、ファイル内の資格情報が狙われうる（一次資料未付与） |
| 548/TCP | T1039 | service | T1039 はネットワーク共有上のデータ取得。AFP はファイル共有プロトコル |
| 593/TCP | T1046 | reference | RPC over HTTP のエンドポイントマッパーは RPC インターフェースの列挙に使われうる（一次資料未付与） |
| 873/TCP | T1039 | service | T1039 はネットワーク共有上のデータ取得。rsync のモジュールはファイル共有として公開される |
| 2049/TCP | T1039 | service | T1039 はネットワーク共有上のデータ取得。NFS はファイル共有プロトコル |
| 2049/UDP | T1039 | service | T1039 はネットワーク共有上のデータ取得。NFS はファイル共有プロトコル |
| 2179/TCP | T1021 | service | VMConnect は Hyper-V の VM コンソールへのリモート接続を受け付けるサービス |
| 2483/TCP | T1078.001 | reference | Oracle の既定アカウント悪用の可能性（一次資料未付与） |
| 3283/TCP | T1021.005 | reference | Apple Remote Desktop は画面共有に VNC 系の仕組みを使う（3283/tcp との対応は一次資料未付与） |

## DET0118 の監視ポートと通信方式の根拠

| analytic | ポート | port_basis | transport_basis |
|---|---|---|---|
| DET0118/AN0327 | 445/tcp 135/tcp 3389/tcp 5985/tcp 5986/tcp 1433/tcp 3306/tcp | official | service_default |
| DET0118/AN0328 | 22/tcp 445/tcp 2049/tcp 80/tcp 443/tcp 3306/tcp 5432/tcp 6379/tcp 21/tcp | inferred | service_default |
| DET0118/AN0329 | 427/tcp 443/tcp 902/tcp 5989/tcp | official | stated |
| DET0118/AN0330 | 22/tcp 5900/tcp 8080/tcp 8443/tcp | official | service_default |

- stated: analytic 本文に通信方式の記載あり（例: `tcp/427`） / service_default: 番号のみの記載で、サービスの標準通信方式を採用
- ポートとの照合は (番号, 通信方式) の一致のみ。番号だけの一致では紐付けない。

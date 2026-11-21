"""Curated part of data/vulnerabilities.json: which risk text mentions the CVE and under which condition it applies.

Everything else (product, versions, CVSS, dates, KEV) is taken verbatim from the official records in data/raw/
by tools/import_cve.py. A CVE is never attached to a port number by itself.
"""

CVES = {
    "CVE-2017-0144": {
        "risk_ids": ["RISK-00445-TCP"], "service_ids": ["SRV-SMB"],
        "condition": "記載の Windows の SMBv1 サーバ（細工したパケットで任意コード実行）。445/tcp が開いているだけでは該当しない",
        "notes": "リスク評価の『MS17-010 (EternalBlue)』に対応。EternalBlue = CVE-2017-0144 は ATT&CK の手続き例（S0260 InvisiMole）の記載による。MS17-010 との対応は CVE レコードの参照に記載がなく未確認。",
        "source_ids": ["SRC-MITRE-T1210"]},
    "CVE-2019-0708": {
        "risk_ids": ["RISK-03389-TCP"], "service_ids": ["SRV-RDP"],
        "condition": "影響バージョンの Windows の Remote Desktop Services に、未認証の攻撃者が RDP で接続した場合（affected を参照）",
        "notes": "BlueKeep = CVE-2019-0708 は ATT&CK の手続き例（S0260 InvisiMole）の記載による。", "source_ids": ["SRC-MITRE-T1210"]},
    "CVE-2022-21893": {
        "risk_ids": ["RISK-03389-TCP"], "service_ids": ["SRV-RDP"],
        "condition": "影響バージョンの Windows で Remote Desktop Protocol を利用している場合（affected を参照）", "notes": "", "source_ids": []},
    "CVE-2020-0796": {
        "risk_ids": ["RISK-00445-TCP"], "service_ids": ["SRV-SMB"],
        "condition": "SMB 3.1.1 を処理する Windows 10 / Windows Server のバージョン 1903・1909（affected を参照）", "notes": "通称 SMBGhost（リスク評価の記載。CVE レコードの参照 URL に SMBGhost の名称あり）。",
        "source_ids": []},
    "CVE-2024-6387": {
        "risk_ids": ["RISK-00022-TCP"], "service_ids": ["SRV-SSH"],
        "condition": "影響バージョンの OpenSSH サーバ（sshd）。ディストリビューションの修正状況は各ベンダー情報を確認", "notes": "通称 regreSSHion（リスク評価の記載）。",
        "source_ids": []},
    "CVE-2021-21974": {
        "risk_ids": ["RISK-00427-TCP"], "service_ids": [],
        "condition": "OpenSLP を使う影響バージョンの VMware ESXi に、同一ネットワークセグメントから 427 へ到達できる場合（affected を参照）", "notes": "", "source_ids": []},
    "CVE-2023-46604": {
        "risk_ids": ["RISK-61616-TCP"], "service_ids": [],
        "condition": "影響バージョンの Apache ActiveMQ の Java OpenWire ブローカー・クライアント。ポート番号だけでは判定できない",
        "notes": "", "source_ids": ["SRC-APACHE-CVE-2023-46604", "SRC-NVD-CVE-2023-46604"]},
}

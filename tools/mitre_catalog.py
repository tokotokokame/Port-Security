"""MITRE ATT&CK catalog verified against attack.mitre.org on 2026-11-21.

Only facts read from the official pages are recorded here. Analytic platforms
that the pages did not state explicitly are left as None.
"""
VERIFIED = "2026-11-21"

# id: (name, tactics, version, created, last_modified, [det_ids], {sub_id: sub_name})
TECHNIQUES = {
    "T1003": ("OS Credential Dumping", ["Credential Access"], "2.2", None, "2026-06-13", ["DET0234"], {}),
    "T1021": ("Remote Services", ["Lateral Movement"], "1.6", None, "2026-11-03", ["DET0269"], {
        "T1021.001": "Remote Desktop Protocol", "T1021.002": "SMB/Windows Admin Shares",
        "T1021.004": "SSH", "T1021.005": "VNC", "T1021.006": "Windows Remote Management"}),
    "T1040": ("Network Sniffing", ["Credential Access", "Discovery"], "1.7", None, "2026-05-12", ["DET0314"], {}),
    "T1041": ("Exfiltration Over C2 Channel", ["Exfiltration"], "2.4", None, "2026-09-11", ["DET0348"], {}),
    "T1071": ("Application Layer Protocol", ["Command and Control"], "2.4", None, "2026-09-03", ["DET0444"], {
        "T1071.001": "Web Protocols", "T1071.004": "DNS"}),
    "T1110": ("Brute Force", ["Credential Access"], "2.8", "2017-05-31", "2026-11-03", ["DET0463"], {
        "T1110.001": "Password Guessing", "T1110.002": "Password Cracking", "T1110.003": "Password Spraying"}),
    "T1210": ("Exploitation of Remote Services", ["Lateral Movement"], "1.2", "2018-04-18", "2026-08-04", ["DET0118"], {}),
    "T1486": ("Data Encrypted for Impact", ["Impact"], "1.5", None, "2026-05-12", ["DET0215"], {}),
    "T1552": ("Unsecured Credentials", ["Credential Access"], "1.5", None, "2025-10-24", [], {
        "T1552.001": "Credentials In Files"}),
    "T1557": ("Adversary-in-the-Middle", ["Credential Access", "Collection"], "2.5", None, "2026-11-03", ["DET0296"], {
        "T1557.001": "Name Resolution Poisoning and SMB Relay"}),
    "T1558": ("Steal or Forge Kerberos Tickets", ["Credential Access"], "1.7", None, "2026-05-12", ["DET0522"], {
        "T1558.003": "Kerberoasting", "T1558.004": "AS-REP Roasting"}),
    "T1595": ("Active Scanning", ["Reconnaissance"], "1.0", None, "2025-10-24", ["DET0830"], {
        "T1595.002": "Vulnerability Scanning"}),
}

# det_id: (name, technique_id, source_id, [analytic_ids])  -- analytics without detail
DETECTION_STRATEGIES = {
    "DET0234": ("Credential Dumping via Sensitive Memory and Registry Access Correlation", "T1003", "SRC-MITRE-T1003", ["AN0648", "AN0649", "AN0650"]),
    "DET0269": ("Behavioral Detection Strategy for Remote Service Logins and Post-Access Activity", "T1021", "SRC-MITRE-T1021", []),
    "DET0314": ("Detection Strategy for Network Sniffing Across Platforms", "T1040", "SRC-MITRE-DET0314", ["AN0875", "AN0876", "AN0877", "AN0878", "AN0879"]),
    "DET0348": ("Detection Strategy for Exfiltration Over C2 Channel", "T1041", "SRC-MITRE-DET0348", ["AN0988", "AN0989", "AN0990", "AN0991"]),
    "DET0444": ("Detection of Command and Control Over Application Layer Protocols", "T1071", "SRC-MITRE-T1071", []),
    "DET0463": ("Brute Force Authentication Failures with Multi-Platform Log Correlation", "T1110", "SRC-MITRE-T1110", ["AN1275", "AN1276", "AN1277", "AN1278", "AN1279"]),
    "DET0215": ("Detection of Multi-Platform File Encryption for Impact", "T1486", "SRC-MITRE-T1486", []),
    "DET0296": ("Detect Adversary-in-the-Middle via Network and Configuration Anomalies", "T1557", "SRC-MITRE-T1557", ["AN0823", "AN0824", "AN0825", "AN0826"]),
    "DET0522": ("Detect Kerberos Ticket Theft or Forgery", "T1558", "SRC-MITRE-T1558", ["AN1443", "AN1444", "AN1445"]),
    "DET0830": ("Detection of Active Scanning", "T1595", "SRC-MITRE-T1595", []),
}

# DET0118 analytics, ports exactly as listed on the official page.
DET0118 = {
    "name": "Exploitation of Remote Services – multi-platform lateral movement detection",
    "version": "1.0", "created": "2025-10-21", "last_modified": "2026-05-12",
    "analytics": [
        ("AN0327", "Windows", [445, 135, 3389, 5985, 5986, 1433, 3306], "official", [], "LOG-WIN-AN0327"),
        ("AN0328", "Linux", [22, 445, 2049, 80, 443, 3306, 5432, 6379, 21], "inferred",
         ["sshd", "smbd", "nfsd", "httpd/nginx", "mysqld", "postgres", "redis", "vsftpd"], "LOG-LIN-AN0328"),
        ("AN0329", "ESXi", [427, 443, 902, 5989], "official", [], "LOG-ESXI-AN0329"),
        ("AN0330", "macOS", [22, 5900, 8080, 8443], "official", [], "LOG-MAC-AN0330"),
    ],
}

DET0463_DESC = {
    "AN1275": "High volume of failed logon attempts followed by a successful one from a suspicious user, host, or timeframe",
    "AN1276": "Multiple authentication failures for valid or invalid users followed by success from same IP/user",
    "AN1277": "Password spraying or brute force attempts across user pool within short time intervals",
    "AN1278": "Multiple failed authentications in unified logs (e.g., loginwindow or sshd)",
    "AN1279": "Excessive login attempts followed by success from SaaS apps like O365, Dropbox, etc.",
}

# Extra sources fetched directly (detection strategy pages)
DET_PAGES = {"DET0314": "2026-11-21", "DET0348": "2026-11-21"}

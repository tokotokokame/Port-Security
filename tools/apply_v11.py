#!/usr/bin/env python3
"""v1.1 data corrections (idempotent). Every change is backed by a primary source checked on 2026-11-22.

Usage: python3 tools/apply_v11.py   (then: validate.py / quality.py / build_index.py)
"""
import json
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data"
DAY = "2026-11-22"
MS_LEARN = "Microsoft Learn 公式ページ本文（検索結果に表示された同一 URL の本文）"
GH = "https://raw.githubusercontent.com/"


def load(f): return json.loads((DATA / f"{f}.json").read_text(encoding="utf-8"))
def save(f, v): (DATA / f"{f}.json").write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
def by_id(recs): return {(r.get("id") or r.get("source_id")): r for r in recs}


# ---------------------------------------------------------------- Phase 1: 出典の確認状態
SOURCE_FIX = {
    "SRC-HYDRA": (GH + "vanhauser-thc/thc-hydra/master/README",
                  "README の対応プロトコル一覧に FTP / HTTP / RDP / SMB / SSH / Telnet などを記載。"),
    "SRC-NMAP": (GH + "nmap/nmap/master/docs/nmap.1",
                 "公式 man page: 'Network exploration tool and security / port scanner'。サービス・バージョン・OS の識別機能を記載。"),
    "SRC-SAMBA-SMBCLIENT": (GH + "samba-team/samba/master/docs-xml/manpages/smbclient.1.xml",
                            "man page の -p オプション: SMB/CIFS サーバの標準 TCP ポートは 139（既定）。445/tcp は本資料に記載なし。"),
    "SRC-MS-RDS": (GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/remote/ports-used-by-rds.md",
                   "RDS の役割別ポート: TCP 88 / TCP 135 / TCP・UDP 389 / TCP 636 / TCP 443 / TCP・UDP 3389 / TCP 5985 を記載。UDP 88・TCP 5986 は記載なし。"),
    "SRC-IETF-RFC": ("https://www.rfc-editor.org/info/rfc6335",
                     "6章: TCP / UDP / UDP-Lite / SCTP / DCCP は 16 bit のポート空間を持ち、System(0-1023) / User(1024-49151) / Dynamic(49152-65535) に区分。"),
    "SRC-IANA-PROTO": ("data/raw/iana/protocol-numbers-1.csv",
                       "IANA 公式 CSV（iana.yml で取得）と protocols.json の番号・キーワードを照合（Q-IPPROTO）。"),
    "SRC-MITRE-ATTACK": ("https://github.com/mitre-attack/attack-stix-data",
                         "公式 STIX v20.1（data/raw/mitre/attack_catalog.json に ID・名称・廃止状態を収録）。"),
}
for e, title in {"4624": "An account was successfully logged on", "4625": "An account failed to log on",
                 "4648": "A logon was attempted using explicit credentials", "4662": "An operation was performed on an object",
                 "4697": "A service was installed in the system", "4768": "A Kerberos authentication ticket (TGT) was requested",
                 "4771": "Kerberos pre-authentication failed", "4776": "The computer attempted to validate the credentials for an account",
                 "5140": "A network share object was accessed",
                 "5145": "A network share object was checked to see whether client can be granted desired access"}.items():
    SOURCE_FIX[f"SRC-MS-EVT-{e}"] = (MS_LEARN, f"イベント {e} の名称 '{title}' と説明を確認。")

NEW_SOURCES = [{
    "source_id": "SRC-MS-SVC-PORTS", "title": "Service overview and network port requirements for Windows", "publisher": "Microsoft",
    "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/service-overview-and-network-port-requirements",
    "document_type": "Vendor Documentation", "applicable_data": "Windows のサービス別ポート要件（Kerberos UDP 88、WinRM 2.0 TCP 5985/5986 など）",
    "publication_date": None, "last_updated": None, "access_date": DAY, "verification_status": "確認済み",
    "notes": "表に Kerberos TCP/UDP 88、WinRM 2.0 の既定 HTTP TCP 5985 / HTTPS TCP 5986 を記載。", "scope": ["service", "port_assignment"],
    "reverified_v4": True,
    "verified_via": GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/networking/service-overview-and-network-port-requirements.md"}]

# v3 から継承した CISA 出典はタイトルと URL が別資料を指していた。タイトル側（PDF）の本文で確認できた内容に合わせる。
CISA_HYGIENE = {
    "title": "Cyber Risk and Cyber Hygiene Services (Chemical Security Summit 2022)",
    "url": "https://www.cisa.gov/sites/default/files/2022-12/summit-2022-cyber-risks-cyber-hygiene-508.pdf",
    "notes": "本文: SMB, NetBIOS, Kerberos, LDAP, Telnet はインターネットに公開すべきでない（即時対処が必要）。RDP は確認した本文に記載なし。",
    "access_date": DAY, "verification_status": "確認済み", "reverified_v4": True, "verified_via": "CISA 公式 PDF（検索結果に表示された本文）"}

# 出典の付け替え: (ポート, 外す出典, 付ける出典, 理由)
REASSIGN = [("PORT-00088-UDP", "SRC-MS-RDS", "SRC-MS-SVC-PORTS", "RDS 資料に UDP 88 の記載なし"),
            ("PORT-05986-TCP", "SRC-MS-RDS", "SRC-MS-SVC-PORTS", "RDS 資料に TCP 5986 の記載なし"),
            ("PORT-03389-TCP", "SRC-CISA-HYGIENE", None, "CISA 資料の本文に RDP の記載なし")]

# ---------------------------------------------------------------- Phase 1: 確認済みポートの根拠
DET0118 = {"AN0327": "ServicePortSet (default: 445,135,3389,5985,5986,1433,3306)",
           "AN0329": "NSM:Flow: Inbound to tcp/427, tcp/443, tcp/902, tcp/5989",
           "AN0330": "ServicePortSet: 22, 5900, 8080/8443 by default"}
DET_PORTS = {"PORT-00135-TCP": "AN0327", "PORT-00445-TCP": "AN0327", "PORT-01433-TCP": "AN0327", "PORT-03306-TCP": "AN0327",
             "PORT-03389-TCP": "AN0327", "PORT-05985-TCP": "AN0327", "PORT-05986-TCP": "AN0327", "PORT-00427-TCP": "AN0329",
             "PORT-00902-TCP": "AN0329", "PORT-05989-TCP": "AN0329", "PORT-00022-TCP": "AN0330", "PORT-05900-TCP": "AN0330"}
AMP = {"PORT-00017-UDP": "Quote of the Day (QOTD)", "PORT-00019-UDP": "Character Generator Protocol (CharGEN)",
       "PORT-00111-UDP": "Portmap/Remote Procedure Call (RPC)", "PORT-00520-UDP": "Routing Information Protocol version 1 (RIPv1)",
       "PORT-01900-UDP": "Simple Service Discovery Protocol (SSDP)", "PORT-05353-UDP": "Multicast Domain Name System (mDNS)",
       "PORT-11211-UDP": "Memcached（UDP/TCP 11211 の反射攻撃を記載）"}

TOOL_NOTES = {"TOOL-SMBCLIENT": "man page では -p の既定は TCP 139。445/tcp は本資料に記載がなく、SMB over TCP の IANA 割当に基づく。",
              "TOOL-HYDRA": "README で対応プロトコルを確認。ポートは各プロトコルの標準ポート（IANA）で、ツール固有の値ではない。痕跡は総当たりの一般的な特徴。"}


def phase1():
    src = load("sources"); s = by_id(src)
    for sid, (via, note) in SOURCE_FIX.items():
        s[sid].update(verification_status="確認済み", reverified_v4=True, access_date=DAY, verified_via=via, notes=note)
    s["SRC-IETF-RFC"]["title"] = "RFC 6335: IANA Procedures for the Management of the Service Name and Transport Protocol Port Number Registry"
    s["SRC-CISA-HYGIENE"].update(CISA_HYGIENE)
    for n in NEW_SOURCES:
        if n["source_id"] not in s: src.append(n)
    save("sources", src)

    ports = load("ports"); P = by_id(ports)
    for pid, old, new, _ in REASSIGN:
        ids = P[pid]["source_ids"]
        if old in ids: ids.remove(old)
        if new and new not in ids: ids.append(new)
    def add(p, ev):
        if not any(e["source_id"] == ev["source_id"] and e["kind"] == ev["kind"] for e in p.setdefault("evidence", [])):
            p["evidence"].append(ev)
    for pid, an in DET_PORTS.items():
        add(P[pid], {"source_id": "SRC-MITRE-DET0118", "technique": "T1210", "kind": "ATT&CK検知戦略", "examples": [an], "keyword": DET0118[an]})
    for pid, name in AMP.items():
        add(P[pid], {"source_id": "SRC-CISA-AMP", "technique": "T1498.002", "kind": "政府勧告", "examples": [],
                     "keyword": f"TA14-017A の Systems Affected に {name} を記載"})
    add(P["PORT-04444-TCP"], {"source_id": "SRC-METASPLOIT-REVSHELL", "technique": None, "kind": "公式文書", "examples": [],
                              "keyword": "公式ドキュメントのリバースシェル例で LPORT=4444 を使用（フレームワークの既定値ではない: Opt::LPORT default=nil）"})
    save("ports", ports)

    tools = load("tools"); T = by_id(tools)
    for tid, note in TOOL_NOTES.items(): T[tid]["unconfirmed_notes"] = note
    save("tools", tools)


# ---------------------------------------------------------------- Phase 2: 通信方式と IP プロトコル番号
LAYER = {"PROTO-TCP": ("L4", True), "PROTO-UDP": ("L4", True), "PROTO-SCTP": ("L4", True),
         "PROTO-ICMP": ("L3", False), "PROTO-GRE": ("L3", False), "PROTO-ESP": ("L3", False), "PROTO-AH": ("L3", False)}


# service_name は IANA 登録名に統一し、慣用名は formal_name に残す（data/raw/iana の CSV で照合）
IANA_NAME = {
    "PORT-00443-UDP": ("https", "HTTP/3 over QUIC（IANA 登録名は https）", None, None),
    "PORT-00514-TCP": ("shell", "rsh（IANA 登録）/ Syslog over TCP（慣用）", None,
                       "IANA の 514/tcp は shell（rsh）。syslog の TCP 送信に 514 を使うのは慣用で IANA 登録ではない（RFC 3195 の syslog-conn は 601/tcp）。"),
    "PORT-05900-TCP": ("rfb", "Virtual Network Computing (VNC) / RFB", None, None),
    "PORT-06000-TCP": ("x11", "X11", "X Window System", None),
    "PORT-06667-TCP": ("ircu", "IRC", "IRCU", None),
    "PORT-08443-TCP": ("pcsync-https", "HTTPS Alternate（慣用。IANA 登録名は pcsync-https）", None, None),
}


def phase2():
    """services: ports as (number, transport) derived from the port records that reference them.
    protocols: separate the IP protocol number from the layer description; flag which ones carry port numbers."""
    ports = load("ports"); P = by_id(ports)
    for pid, (name, formal, desc, note) in IANA_NAME.items():
        p = P[pid]; p.update(service_name=name, formal_name=formal)
        if desc: p["iana_description"] = desc
        if note and note not in p["unconfirmed_notes"]:
            p["unconfirmed_notes"] = (p["unconfirmed_notes"] + " " + note).strip()
    save("ports", ports)
    risks = load("port_risks")
    for r in risks:
        pid = f"PORT-{r['port_number']:05d}-{r['transport_protocol']}"
        if pid in IANA_NAME: r["service_name"] = IANA_NAME[pid][0]
    save("port_risks", risks)
    services = load("services")
    for s in services:
        s["ports"] = sorted([p["port_number"], p["transport_protocol"]] for p in ports if p["service_id"] == s["id"])
    save("services", services)
    protos = load("protocols")
    for p in protos:
        layer, has_ports = LAYER[p["id"]]
        p.update(ip_protocol_number=p["protocol_number"], layer=layer, has_port_numbers=has_ports)
    save("protocols", protos)


if __name__ == "__main__":
    phase1(); phase2()
    print("applied: phase1, phase2")

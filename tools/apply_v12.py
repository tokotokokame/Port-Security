#!/usr/bin/env python3
"""v1.2 data corrections (idempotent). Each change cites the original document checked on 2026-11-22.

Usage: python3 tools/apply_v12.py [phase...]   (default: all)  then validate.py / quality.py / build_index.py
"""
import json, re, sys
from pathlib import Path

ROOT = Path(__file__).parent.parent
DATA = ROOT / "data"
DAY = "2026-11-22"
GH = "https://raw.githubusercontent.com/"


def load(f): return json.loads((DATA / f"{f}.json").read_text(encoding="utf-8"))
def save(f, v): (DATA / f"{f}.json").write_text(json.dumps(v, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
def by_id(recs): return {(r.get("id") or r.get("source_id")): r for r in recs}
def sub(text, old, new):
    return text.replace(old, new) if old in text else text


# ================================================================ Phase 1-A: 出典の確認方法（F-12）と scope（F-11）
ORIGINAL = {"original_document", "official_api", "official_stix", "official_repository"}
STATUS = {**{v: "確認済み" for v in ORIGINAL}, "search_result": "一部確認", "not_verified": "未確認"}

# 今回（2026-11-22）原文を取得して照合した出典: id -> (verified_via, 原文の所在, 確認した内容)
CHECKED = {
    "SRC-IANA-PORT": ("original_document", "data/raw/iana/service-names-port-numbers.csv", "IANA 公式 CSV（iana.yml で取得）と ports.json の登録名・説明を照合（Q-IANA）"),
    "SRC-IETF-RFC": ("original_document", "https://www.rfc-editor.org/rfc/rfc6335.html", "6章: TCP, UDP, UDP-Lite, SCTP, DCCP は 16 bit のポート番号空間。System 0-1023 / User 1024-49151 / Dynamic 49152-65535"),
    "SRC-MS-PORTS": ("official_repository", GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/networking/service-overview-and-network-port-requirements.md", "Windows のサービス別ポート要件（Kerberos TCP/UDP 88、WinRM 2.0 TCP 5985/5986 など）"),
    "SRC-MS-HYPERV-LM": ("official_repository", GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/virtualization/troubleshoot-live-migration-guidance.md", "TCP 6600 と 3343（クラスタ）の待受確認を記載"),
    "SRC-MS-HYPERV-CONN": ("official_repository", GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/virtualization/hyper-v-cluster-connectivity-management-configuration.md", "VMConnect のポート 2179 を記載"),
    "SRC-MS-HYPERV-TS": ("official_repository", GH + "MicrosoftDocs/SupportArticles-docs/main/support/windows-server/virtualization/hyper-v-virtual-machine-input-migration-integration.md", "Hyper-V-Worker のイベント 18502（VM の電源断）を記載"),
    "SRC-ORACLE-VBOX-TS": ("original_document", "https://docs.oracle.com/en/virtualization/virtualbox/7.1/user/Troubleshooting.html", "VM 起動ごとに VBox.log を作成し、既定で VM のログフォルダに置くと記載"),
    "SRC-ORACLE-VBOX-VRDP": ("original_document", "https://docs.oracle.com/en/virtualization/virtualbox/7.2/user/remotevm.html", "VRDP サーバーの既定は TCP 3389"),
    "SRC-ORACLE-VBOX-WEB": ("original_document", "https://docs.oracle.com/en/virtualization/virtualbox/6.0/admin/vboxwebsrv-daemon.html", "vboxwebsrv の既定は HOST=localhost、PORT=18083"),
    "SRC-KERBRUTE": ("official_repository", GH + "ropnop/kerbrute/master/README.md", "事前認証の失敗は 4625 を発生させず、4768 / 4771 を発生させると記載"),
    "SRC-CHISEL": ("official_repository", GH + "jpillora/chisel/master/README.md", "HTTP 上のトンネル。--port の既定は環境変数 PORT、なければ 8080"),
    "SRC-EVILWINRM": ("official_repository", GH + "Hackplayers/evil-winrm/master/README.md", "README: ハッキング・ペネトレーションテスト用の WinRM シェル"),
    "SRC-METASPLOIT-REVSHELL": ("official_repository", GH + "rapid7/metasploit-framework/master/docs/metasploit-framework.wiki/How-to-use-a-reverse-shell-in-Metasploit.md", "リスナー例で LPORT 4444 を使用（Opt::LPORT の既定値は nil）"),
    "SRC-CISA-HYGIENE": ("original_document", "https://www.cisa.gov/sites/default/files/2022-12/summit-2022-cyber-risks-cyber-hygiene-508.pdf",
                         "Exposed Vulnerable Services のスライドに SMB / NetBIOS / Kerberos / LDAP / Telnet / FTP / RDP / SMTP / POP3 / IMAP / DNS。SMB・NetBIOS・Kerberos・LDAP・Telnet は『インターネットに公開すべきでない』。SSH は暗号の脆弱性の文脈のみで、露出の対象には含まれない"),
    "SRC-DOCKER-REMOTE": ("official_repository", GH + "docker/docs/main/content/manuals/engine/daemon/remote-access.md", "保護せずに接続を公開すると、リモートの非 root ユーザーがホストの root 権限を得うる"),
    "SRC-DOCKER-PROTECT": ("official_repository", GH + "docker/docs/main/content/manuals/engine/security/protect-access.md", "TLS で保護するデーモンの待受例に 2376"),
    "SRC-REDIS-SECURITY": ("official_repository", GH + "redis/docs/main/content/operate/oss_and_stack/management/security/_index.md", "信頼された環境で信頼されたクライアントが使う設計。多数のインスタンスが公開 IP で放置されている"),
    "SRC-REDIS-ANTIREZ": ("original_document", "https://antirez.com/news/96", "作者が、パスワードなしで公開された Redis で任意ファイル（authorized_keys）を書き込みシェルを得る手順を解説"),
    "SRC-MONGODB-CHECKLIST": ("official_repository", GH + "mongodb/docs/master/source/administration/security-checklist.txt", "アクセス制御の有効化と認証方式の指定、ネットワーク露出の制限を推奨"),
    "SRC-K8S-KUBELET": ("official_repository", GH + "kubernetes/website/main/content/en/docs/reference/access-authn-authz/kubelet-authn-authz.md", "認証されない要求は system:anonymous として扱われ、既定の認可モードは AlwaysAllow。nodes/proxy は他の kubelet API に到達"),
    "SRC-ETCD-SECURITY": ("official_repository", GH + "etcd-io/website/main/content/en/docs/v3.7/op-guide/security.md", "既定では RBAC 認証も転送層の認証も有効でない"),
    "SRC-APACHE-CVE-2023-46604": ("official_repository", GH + "apache/activemq-website/main/src/security-advisories.data/CVE-2023-46604-announcement.txt", "Java OpenWire プロトコルのマーシャラーにリモートコード実行の脆弱性"),
    "SRC-CISA-IPMI": ("original_document", "https://www.cisa.gov/news-events/alerts/2013/07/26/risks-using-intelligent-platform-management-interface-ipmi", "IPMI は OS の制御を上書きできる低レベルのアクセスを与える。IPMI の通信（通常 UDP 623）を制限するよう記載"),
    "SRC-CISCO-TSA18-106A": ("original_document", "https://www.cisco.com/c/en/us/support/docs/csa/cisco-sa-20180416-tsa18-106a.html", "Smart Install を使わないなら無効化を推奨。使う場合は TCP 4786 の受信を ACL で遮断"),
    "SRC-PANW-XPANSE-2021": ("original_document", "https://www.paloaltonetworks.com/blog/2021/05/rsac-attack-surface-management/",
                             "2021-05-19 公開の本文で、観測期間（2021年1〜3月）・対象（50 社・5,000 万 IP）・15〜60 分・Exchange 5 分を確認"),
    "SRC-CISA-AMP": ("search_result", "https://us-cert.cisa.gov/ncas/alerts/TA14-017A", "検索結果に表示された公式ページの本文で Systems Affected の一覧（QOTD / CharGEN / Portmap / SSDP / mDNS / RIPv1 / Memcached 等）を確認。原文ページは取得できず"),
    "SRC-CISA-TA18-106A": ("search_result", "https://us-cert.cisa.gov/ncas/alerts/TA18-106A", "検索結果に表示された公式ページの本文で SMI (port 4786) を確認。原文ページは取得できず"),
    "SRC-MS-HYPERV-EVTLOG": ("not_verified", "https://techcommunity.microsoft.com/blog/virtualization/looking-at-the-hyper-v-event-log-january-2018-edition/382411", "本文を取得できず（取得できたのはメタデータのみ）"),
    "SRC-NVD-CVE-2023-46604": ("not_verified", "https://nvd.nist.gov/vuln/detail/CVE-2023-46604", "本文を取得できず。KEV 掲載は SRC-CISA-KEV、内容は SRC-CVE-2023-46604 で確認"),
    "SRC-FORTINET-DOCS": ("not_verified", "https://docs.fortinet.com/", "サイトのトップページで、特定の資料を指していない（Phase 2 でページ単位の出典に置き換え）"),
    "SRC-NEC-IX": ("not_verified", "https://jpn.nec.com/univerge/ix/", "サイトのトップページで、特定の資料を指していない（Phase 2 でページ単位の出典に置き換え）"),
}
for e in ["4624", "4625", "4648", "4662", "4697", "4768", "4769", "4771", "4776", "5140", "5145"]:
    CHECKED[f"SRC-MS-EVT-{e}"] = ("original_document", f"https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-{e}", None)

SCOPE = {  # F-11: 内容を確認したうえでの再分類
    "tool_documentation": ["SRC-KERBRUTE", "SRC-CHISEL", "SRC-EVILWINRM", "SRC-HYDRA", "SRC-NMAP", "SRC-SAMBA-SMBCLIENT", "SRC-METASPLOIT-REVSHELL"],
    "vendor_security": ["SRC-DOCKER-REMOTE", "SRC-DOCKER-PROTECT", "SRC-REDIS-SECURITY", "SRC-MONGODB-CHECKLIST", "SRC-K8S-KUBELET",
                        "SRC-ETCD-SECURITY", "SRC-APACHE-CVE-2023-46604", "SRC-CISCO-TSA18-106A"],
    "research_report": ["SRC-REDIS-ANTIREZ", "SRC-PANW-XPANSE-2021"],
    "vulnerability_database": ["SRC-NVD-CVE-2023-46604"],
    "government_guidance": ["SRC-CISA-HYGIENE"],
    "attack_technique": ["SRC-MITRE-ICS-" + t for t in ("T0836", "T0869", "T0806", "T0888", "T0846-001", "T0883", "T0885", "T0846-002", "T0871")],
}
REMOVED_DRAFT = ["SRC-MITRE-ICS-T0846"]  # 既存の SRC-MITRE-ICS-T0846-001 と重複するため作成しない
DROP_SCOPE = {"threat_advisory", "threat_guidance", "service"}  # 上の出典から外す旧分類

NEW_SOURCES = [
    {"source_id": "SRC-PANW-XPANSE-2021", "title": "Cortex Xpanse Researchers Identify Missing Metric for a Modern SOC (2021 Attack Surface Threat Report)",
     "publisher": "Palo Alto Networks", "url": "https://www.paloaltonetworks.com/blog/2021/05/rsac-attack-surface-management/",
     "document_type": "Research Report", "applicable_data": "CVE 公表から探索スキャン開始までの時間（2021年1〜3月の観測）",
     "publication_date": "2021-05-19", "last_updated": None, "access_date": DAY, "verification_status": "確認済み",
     "notes": "2021年1〜3月、50 社のグローバル企業に関係する 5,000 万 IP を観測。攻撃者の探索スキャンの多くは CVE 公表から 15〜60 分後に始まり、Exchange（3月2日公表）では 5 分以内。Unit 42 の 2022 年報告（2022-07-26）はこの報告を『通常 15 分以内』と要約",
     "scope": ["research_report"], "reverified_v4": True},
    {"source_id": "SRC-MITRE-T1213", "title": "T1213 Data from Information Repositories", "publisher": "The MITRE Corporation",
     "url": "https://attack.mitre.org/techniques/T1213/", "document_type": "MITRE ATT&CK", "applicable_data": "T1213 Data from Information Repositories",
     "publication_date": None, "last_updated": None, "access_date": DAY, "verification_status": "確認済み", "notes": "",
     "scope": ["attack_technique"], "reverified_v4": True},
]
MERGED = {"SRC-MS-SVC-PORTS": "SRC-MS-PORTS"}  # F-19: 同一 URL。ID は残し参照を移す


def refs(db):
    used = {}
    for f, recs in db.items():
        if f == "sources": continue
        for r in recs:
            for s in r.get("source_ids", []) + [e["source_id"] for e in r.get("evidence", [])] + \
                     [s for x in r.get("vendor_logs", []) for s in x.get("source_ids", [])]:
                used[s] = used.get(s, 0) + 1
            for k in ("content_source_ids",):
                for s in r.get(k, []): used[s] = used.get(s, 0) + 1
            if f == "port_risks":
                for e in r.get("review", {}).get("evidence", []): used[e["source_id"]] = used.get(e["source_id"], 0) + 1
    return used


def phase1_sources():
    src = [s for s in load("sources") if s["source_id"] not in REMOVED_DRAFT]; S = by_id(src)
    for n in NEW_SOURCES:
        if n["source_id"] not in S: src.append(n); S[n["source_id"]] = n
    for s in src:
        sid = s["source_id"]; old = s.get("verified_via")
        url_like = isinstance(old, str) and (old.startswith("http") or old.startswith("data/"))
        if url_like and not s.get("verified_url"): s["verified_url"] = old
        if sid in CHECKED:
            via, where, note = CHECKED[sid]
            s.update(verified_via=via, verified_url=where, verified_date=DAY, verified_by="manual_review")
            if note: s["verified_notes"] = note
            if sid.startswith("SRC-MS-EVT-") and not s.get("verified_notes"):
                s["verified_notes"] = "公式ページの見出し（イベント ID と名称）を原文で確認"
        elif sid.startswith("SRC-MITRE-"):
            s.update(verified_via="official_stix", verified_url="data/raw/mitre/attack_catalog.json",
                     verified_date=s.get("verified_date") or s["access_date"], verified_by="automated_import",
                     verified_notes=s.get("verified_notes") or "公式 STIX v20.1 の ID・名称・廃止状態と照合（Q-ATTACK）")
        elif sid.startswith("SRC-SIGMA-"):
            raw = s["url"].replace("https://github.com/SigmaHQ/sigma/blob/", GH + "SigmaHQ/sigma/")
            s.update(verified_via="official_repository", verified_url=raw, verified_date=DAY, verified_by="manual_review",
                     verified_notes=f"SigmaHQ の原文ルールが存在し、title が『{s['title'].removeprefix('Sigma: ')}』であることを確認")
        elif sid.startswith("SRC-CVE-") or sid == "SRC-CISA-KEV":
            s.update(verified_via="official_repository", verified_date=s["access_date"], verified_by="automated_import",
                     verified_notes=s.get("verified_notes") or "公式データ（CVEProject/cvelistV5・cisagov/kev-data）から取込。原文は data/raw/")
        elif url_like and "raw.githubusercontent" in old:
            s.update(verified_via="official_repository", verified_date=s.get("verified_date") or s["access_date"], verified_by="manual_review")
        elif url_like and old.startswith("data/raw"):
            s.update(verified_via="original_document", verified_date=s.get("verified_date") or s["access_date"], verified_by="automated_import")
        elif s.get("verified_via") not in STATUS:
            s.update(verified_via="not_verified", verified_by="manual_review", verified_date=s.get("verified_date") or s["access_date"])
        if not s.get("verified_notes"): s["verified_notes"] = s.get("notes", "")
        s["verification_status"] = STATUS[s["verified_via"]]
        s["reverified_v4"] = s["verification_status"] == "確認済み"
        if not s.get("notes", "").strip(): s["notes"] = s["verified_notes"] or "（確認内容は verified_notes を参照）"
    for scope, ids in SCOPE.items():
        for sid in ids:
            sc = [x for x in S[sid]["scope"] if x not in DROP_SCOPE]
            S[sid]["scope"] = sorted(set(sc + [scope]))
    if "attack_framework" not in S["SRC-MITRE-ATTACK"]["scope"]: S["SRC-MITRE-ATTACK"]["scope"].append("attack_framework")
    for old, new in MERGED.items():
        S[old].update(merged_into=new, notes=f"{new} と同一 URL のため統合（ID は互換のため残す）")
    save("sources", src)
    usage()


UNUSED = {  # F-20: 未使用でも削除しない
    "SRC-MITRE-DET0314": ("未使用・再確認待ち", "DET0314 のレコードは技術の出典（SRC-MITRE-T1040）を参照しており、この出典は未参照"),
    "SRC-MITRE-DET0348": ("未使用・再確認待ち", "DET0348 のレコードは技術の出典（SRC-MITRE-T1041）を参照しており、この出典は未参照"),
    "SRC-MITRE-ICS-T0885": ("未使用・再確認待ち", "T0885 をポートに関連付けるかは Phase 3 の関連区分の見直しで判断"),
    "SRC-FORTINET-DOCS": ("廃止", "サイトのトップページで特定の資料を指さないため、ページ単位の出典（SRC-FTNT-*）に置き換え"),
    "SRC-NEC-IX": ("廃止", "サイトのトップページで特定の資料を指さないため、ページ単位の出典（SRC-NEC-IX2235-DL・SRC-NEC-IX-FAQ-LOG）に置き換え"),
}


def usage():
    src = load("sources"); db = {f.stem: load(f.stem) for f in DATA.glob("*.json") if f.stem != "sources"}
    used = refs(db)
    for s in src:
        sid = s["source_id"]
        if sid in MERGED: s["usage_status"] = "廃止"
        elif sid in used: s["usage_status"] = "使用中"; s.pop("usage_notes", None)
        else:
            st, note = UNUSED.get(sid, ("未使用・再確認待ち", "参照するレコードがない"))
            s["usage_status"] = st; s["usage_notes"] = note
    save("sources", src)


# ================================================================ Phase 1-B: 本文の帰属修正（F-01〜F-03）
TEXT_FIX = {
    ("attack_patterns", "ATK-VULN-SCAN", "attack_features"): (
        "CISA分析によればCVE公表後15分以内に無差別探索スキャンが発生。",
        "Palo Alto Networks の観測（2021年1〜3月、50 社・5,000 万 IP）では、探索スキャンの多くが CVE 公表から 15〜60 分後に始まった（Exchange では 5 分以内）。"),
    ("port_risks", "RISK-03389-TCP", "evaluation_factors.external_exposure"): ("(CISA Bad Practice)", "(CISA は RDP を露出した脆弱なサービスの例に挙げる)"),
    ("port_risks", "RISK-00445-TCP", "evaluation_factors.external_exposure"): ("(CISA緊急勧告)", "(CISA: SMB はインターネットに公開すべきでない)"),
    ("port_risks", "RISK-00445-TCP", "mitigation_controls"): ("(CISA最優先遮断勧告)", "(CISA: SMB はインターネットに公開すべきでない)"),
    ("port_risks", "RISK-00023-TCP", "reason_targeted"): ("(CISA Bad Practice)", "(CISA: Telnet はインターネットに公開すべきでない)"),
    ("port_risks", "RISK-00023-TCP", "evaluation_factors.known_vulnerabilities"): ("Miraiボットネット等によるデフォルトパスワードの乱用", "既定・推測可能なパスワードの悪用（総当たりの主な対象: ATT&CK T1110.001）"),
    ("ports", "PORT-00023-TCP", "malicious_exploitation_cases"): ("デフォルトパスワードによるボットネット(Mirai)感染", "デフォルトパスワードによるボットネット感染"),
    ("ports", "PORT-00138-UDP", "recommended_defenses"): ("(CISA Bad Practice)", "(CISA: NetBIOS はインターネットに公開すべきでない)"),
    ("ports", "PORT-00389-UDP", "recommended_defenses"): ("(CISA要請)", "(CISA: LDAP はインターネットに公開すべきでない)"),
    ("ports", "PORT-00445-TCP", "recommended_defenses"): ("(CISA緊急勧告)", "(CISA: SMB はインターネットに公開すべきでない)"),
}
SOURCE_LINKS = [  # (file, id, add, remove)
    ("attack_patterns", "ATK-VULN-SCAN", ["SRC-PANW-XPANSE-2021"], []),
    ("port_risks", "RISK-00022-TCP", [], ["SRC-CISA-HYGIENE"]),             # SSH は露出サービスの一覧にない
    ("ports", "PORT-03389-TCP", ["SRC-CISA-HYGIENE"], []),                    # v1.1 の解除は検索結果の誤読。原文に RDP あり
    ("ports", "PORT-00389-UDP", ["SRC-CISA-HYGIENE"], []),
    ("attack_patterns", "ATK-REMOTE-EXPLOIT", ["SRC-CISA-KEV"], []),
]


def get(r, path):
    for k in path.split(".")[:-1]: r = r[k]
    return r, path.split(".")[-1]


def phase1_text():
    for f in ("attack_patterns", "port_risks", "ports"):
        recs = load(f); R = by_id(recs)
        for (ff, rid, path), (old, new) in TEXT_FIX.items():
            if ff != f: continue
            obj, k = get(R[rid], path); obj[k] = sub(obj[k], old, new)
        for ff, rid, add, rm in SOURCE_LINKS:
            if ff != f: continue
            ids = R[rid]["source_ids"]
            for s in rm:
                if s in ids: ids.remove(s)
            for s in add:
                if s not in ids: ids.append(s)
        for r in recs:  # F-19: 統合した出典への参照を移す
            r["source_ids"] = list(dict.fromkeys(MERGED.get(s, s) for s in r["source_ids"]))
            for e in r.get("evidence", []): e["source_id"] = MERGED.get(e["source_id"], e["source_id"])
        if f == "ports":
            p = R["PORT-04444-TCP"]
            if not any(e["source_id"] == "SRC-MITRE-T1571" for e in p["evidence"]):
                p["evidence"].append({"source_id": "SRC-MITRE-T1571", "technique": "T1571", "kind": "手順例", "examples": ["C0032", "DarkVishnya"],
                                      "keyword": "T1571 の手続き例で C0032（TEMP.Veles）と DarkVishnya が 4444 を C2 に使用"})
            if "SRC-MITRE-T1571" not in p["source_ids"]: p["source_ids"].append("SRC-MITRE-T1571")
            ev = next(e for e in R["PORT-61616-TCP"]["evidence"] if "KEV" in e["keyword"])
            ev["source_id"] = "SRC-CISA-KEV"
            if "SRC-CISA-KEV" not in R["PORT-61616-TCP"]["source_ids"]: R["PORT-61616-TCP"]["source_ids"].append("SRC-CISA-KEV")
            for pid, svc in (("PORT-00021-TCP", "FTP (21/TCP)"), ("PORT-00023-TCP", "Telnet (23/TCP)"), ("PORT-00389-TCP", "LDAP (389/TCP)")):
                p = R[pid]
                if not any(e["source_id"] == "SRC-MITRE-T1110" and e.get("technique") == "T1110.001" for e in p.get("evidence", [])):
                    p.setdefault("evidence", []).append({"source_id": "SRC-MITRE-T1110", "technique": "T1110.001", "kind": "技術説明",
                                                         "examples": [], "keyword": f"T1110.001 の説明で {svc} を総当たりの主な対象に列挙"})
                if "T1110.001" not in p["technique_ids"]: p["technique_ids"].append("T1110.001")
                if "SRC-MITRE-T1110" not in p["source_ids"]: p["source_ids"].append("SRC-MITRE-T1110")
        save(f, recs)
    for f in ("services", "tools", "log_investigation"):
        recs = load(f)
        for r in recs: r["source_ids"] = list(dict.fromkeys(MERGED.get(s, s) for s in r["source_ids"]))
        save(f, recs)


# ================================================================ Phase 1-C: 攻撃手法の確度分離（F-08・F-09）


def phase1_attacks():
    atk = load("attack_patterns"); techs = {s["id"] for t in load("mitre_techniques") for s in [t] + t["subtechniques"]}
    for a in atk:
        note = a.get("unconfirmed_notes", "")
        if note and ("に正しく分類" in note or "正式定義" in note or "に対応" in note or "を明記" in note or "完全合致" in note or "を割り当て" in note):
            note = ""
        a["attack_mapping_status"] = "確認済み" if all(t in techs for t in a["technique_ids"]) else "一部確認"
        a["content_source_ids"] = ["SRC-PANW-XPANSE-2021"] if a["id"] == "ATK-VULN-SCAN" else a.get("content_source_ids", [])
        a["content_verification_status"] = "一部確認"
        content_note = "説明・特徴・検知方法・対策の各文は出典との逐条照合を未実施（ATT&CK で確認したのは技術分類のみ）。"
        if a["id"] == "ATK-VULN-SCAN": content_note = "特徴の統計は SRC-PANW-XPANSE-2021 で確認。それ以外の文は出典との逐条照合を未実施。"
        a["unconfirmed_notes"] = content_note if not note or note == content_note else note
        a["certainty"] = "一部確認"  # 互換用の総合値は弱い方に合わせる（本文が一部確認）
    save("attack_patterns", atk)  # 移した変更履歴の原文は docs/DATA_CHANGELOG.md（v1.2 Phase 1）に記載


# ================================================================ Phase 1-D: High 27 件の再検証（F-13）
KEEP = {  # 一次資料で悪用・攻撃対象として確認できたもの
    "RISK-00021-TCP": [("SRC-MITRE-T1110", "T1110.001 の説明で FTP (21/TCP) を総当たりの主な対象に列挙"), ("SRC-MITRE-T1048", "T1048.003 の説明に FTP による持ち出し")],
    "RISK-00023-TCP": [("SRC-MITRE-T1110", "T1110.001 の説明で Telnet (23/TCP) を総当たりの主な対象に列挙"), ("SRC-CISA-HYGIENE", "Telnet はインターネットに公開すべきでない")],
    "RISK-00102-TCP": [("SRC-MITRE-ICS-T0846-001", "PLC-Blaster（S1006）がネットワーク上の Siemens S7 PLC を探索して感染（T0846.001 の手続き例）")],
    "RISK-00389-TCP": [("SRC-MITRE-T1110", "T1110.001 の説明で LDAP (389/TCP) を総当たりの主な対象に列挙"), ("SRC-CISA-HYGIENE", "LDAP はインターネットに公開すべきでない")],
    "RISK-03283-TCP": [("SRC-MITRE-T1021", "T1021 の説明に Apple Remote Desktop (ARD) をリモート管理の例として記載")],
    "RISK-05432-TCP": [("SRC-MITRE-T1110", "P.A.S. Webshell（S0598）が PostgreSQL などへの総当たりを行う（T1110.001 の手続き例）"), ("SRC-MITRE-T1213", "T1213.006 の説明に PostgreSQL")],
    "RISK-05984-TCP": [("SRC-CISA-KEV", "CVE-2022-24706（Apache CouchDB の安全でない既定の初期化）が KEV に掲載")],
    "RISK-06443-TCP": [("SRC-MITRE-T1613", "T1613 の説明に Kubernetes API での探索"), ("SRC-MITRE-T1552", "Peirates などが T1552.007（コンテナ API）を悪用する手続き例")],
    "RISK-09200-TCP": [("SRC-CISA-KEV", "Elasticsearch の CVE-2015-1427・CVE-2014-3120（リモートコード実行）が KEV に掲載")],
    "RISK-20000-TCP": [("SRC-MITRE-ICS-T0869", "T0869 の説明に DNP3 を C2 に使われうるプロトコルとして記載")],
    "RISK-27017-TCP": [("SRC-CISA-KEV", "CVE-2025-14847（MongoDB Server の未認証メモリ読み取り）が KEV に掲載")],
    "RISK-44818-TCP": [("SRC-MITRE-ICS-T0871", "CyberAv3ngers の手続き例（T0871）に EtherNet/IP CIP")],
    # 27 件以外で、F-11 の再分類により確認済みの根拠を失った High（同じ基準で再検証）
    "RISK-11211-UDP": [("SRC-MITRE-T1498", "T1498.002 の説明で memcache プロトコルが最大 51,200 倍の増幅を示したと記載（ポート番号の記載はない）")],
    "RISK-04444-TCP": [("SRC-MITRE-T1571", "T1571 の手続き例で C0032（TEMP.Veles）と DarkVishnya が 4444 を C2 に使用")],
}
LOWER = ["RISK-00512-TCP", "RISK-00513-TCP", "RISK-00873-TCP", "RISK-01521-TCP", "RISK-01723-TCP", "RISK-02049-TCP", "RISK-02179-TCP",
         "RISK-03260-TCP", "RISK-03389-UDP", "RISK-06000-TCP", "RISK-06600-TCP", "RISK-07547-TCP", "RISK-11211-TCP", "RISK-18083-TCP",
         "RISK-47808-UDP"]


def phase1_high():
    risks = load("port_risks"); R = by_id(risks)
    for rid, ev in KEEP.items():
        r = R[rid]
        r["source_ids"] = [s for s in r["source_ids"] if s not in REMOVED_DRAFT]
        r["review"] = {"date": DAY, "previous_level": r["review"]["previous_level"] if "review" in r else r["risk_level"], "result": "High を維持",
                       "evidence": [{"source_id": s, "note": n} for s, n in ev]}
        for s, _ in ev:
            if s not in r["source_ids"]: r["source_ids"].append(s)
    for rid in LOWER:
        r = R[rid]
        prev = r["review"]["previous_level"] if "review" in r else r["risk_level"]
        r["review"] = {"date": DAY, "previous_level": prev, "result": "Medium に変更",
                       "evidence": [], "reason": "ATT&CK・KEV・政府勧告で、このサービスの悪用や攻撃対象としての記載を確認できなかった。IANA の登録は攻撃リスクの根拠にしない"}
        r["risk_level"] = "Medium"
    save("port_risks", risks)


THREAT = {"attack_technique", "detection", "threat_advisory"}
DOWNGRADE_NOTE = "v1.2: 根拠がベンダー資料・ツール資料・検索結果のみで、攻撃手法・検知・脅威勧告の再検証済み資料がないため一部確認に変更。"


def phase1_certainty():
    """F-11 の再分類で確認済みの条件を満たさなくなったレコードを一部確認に下げる（根拠を補えたものは除く）。"""
    S = by_id(load("sources"))
    ok = lambda s: S.get(s, {}).get("reverified_v4") and set(S[s]["scope"]) & THREAT
    for f in ("ports", "tools"):
        recs = load(f)
        for r in recs:
            if f == "ports":  # T1110.001 を追加したポートの関連根拠
                for t in r["technique_ids"]:
                    if t == "T1110.001" and not any(b["technique"] == t for b in r["technique_basis"]):
                        r["technique_basis"].append({"technique": t, "relation": "direct", "via": ["SRC-MITRE-T1110"]})
            if r["certainty"] == "一部確認" and DOWNGRADE_NOTE in r["unconfirmed_notes"] and any(ok(s) for s in r["source_ids"]):
                r["certainty"] = "確認済み"  # 根拠を補えたので戻す
                r["unconfirmed_notes"] = r["unconfirmed_notes"].replace(DOWNGRADE_NOTE, "").strip()
            if r["certainty"] == "確認済み" and not any(ok(s) for s in r["source_ids"]):
                r["certainty"] = "一部確認"
                if DOWNGRADE_NOTE not in r["unconfirmed_notes"]:
                    r["unconfirmed_notes"] = (r["unconfirmed_notes"] + " " + DOWNGRADE_NOTE).strip()
        save(f, recs)


# ================================================================ Phase 2: ベンダーログ（F-04 FortiGate / F-05 NEC IX2235）
EVID = ROOT / "data/raw/vendor/fortios_evidence.json"  # tools/vendor_evidence.py が CI で取得した公式ページの抽出結果
FTNT_KEYS = {"LOGREF-13", "LOGID-DEF", "LOGREF-32001", "LOGREF-32002", "LOGREF-39424", "LOGREF-39425", "LOGREF-39426",
             "LOGREF-37138", "LOGREF-37139", "CLI-EXEC-LOG"}
FIELDS = {  # SOC 調査で使うフィールド（すべて公式ページの表にあることを Q-VENDOR が確認）
    "13": ["srcip", "srcport", "srcintf", "dstip", "dstport", "dstintf", "proto", "action", "policyid", "sessionid", "service",
           "duration", "sentbyte", "rcvdbyte", "trandisp", "transip", "transport", "app", "user", "group", "vd", "eventtime", "logid"],
    "32001": ["user", "ui", "srcip", "dstip", "action", "status", "reason", "method", "logdesc"],
    "32002": ["user", "ui", "srcip", "dstip", "action", "status", "reason", "method", "logdesc"],
    "39424": ["user", "group", "remip", "tunneltype", "tunnelid", "action", "reason", "srccountry"],
    "39425": ["user", "group", "remip", "tunneltype", "tunnelid", "action", "reason", "duration", "sentbyte", "rcvdbyte"],
    "39426": ["user", "group", "remip", "tunneltype", "action", "reason", "srccountry"],
    "37138": ["remip", "remport", "locip", "locport", "vpntunnel", "tunnelip", "user", "xauthuser", "action", "outintf"],
    "37139": ["remip", "remport", "locip", "locport", "vpntunnel", "phase2_name", "user", "action"],
}
CLI = ["execute log filter device <device>", "execute log filter category <category>", "execute log filter field <name> <argument 1>", "execute log display"]
SSLVPN_763 = "SRC-FTNT-763-RN-SSLVPN"


def ftnt_sid(page): return "SRC-FTNT-" + page.replace("FGT-", "").replace(".", "")


def phase2_sources():
    ev = json.loads(EVID.read_text(encoding="utf-8")); src = [s for s in load("sources") if "." not in s["source_id"]]; S = by_id(src)
    for page, e in ev["pages"].items():
        key = page.split("-", 2)[2]
        if key not in FTNT_KEYS and page != "FGT-7.6.3-RN-SSLVPN": continue
        ver = e["url"].split("/")[5]; sid = ftnt_sid(page)
        what = (f"Message ID {e['id']} {e['description']}（{e.get('meaning', '')}）type={e.get('type')} / category={e.get('category')}"
                if "id" in e else ("ログ種別とサブ種別の ID 定義" if "LOGID" in page else "execute log コマンドの構文" if "CLI" in page else e.get("statement", "")))
        rec = {"source_id": sid, "title": f"FortiOS {ver} " + ("Log Message Reference" if "LOG" in page else "CLI Reference" if "CLI" in page else "Release Notes")
               + (f" – {e.get('description', '')}" if "id" in e else ""), "publisher": "Fortinet Inc.", "url": e["url"], "document_type": "Vendor Documentation",
               "applicable_data": f"FortiOS {ver}", "publication_date": None, "last_updated": None, "access_date": DAY, "verification_status": "確認済み",
               "notes": what, "scope": ["log_format"], "reverified_v4": True, "verified_via": "original_document", "verified_url": e["url"],
               "verified_date": DAY, "verified_by": "manual_review",
               "verified_notes": f"CI（{ev['check_run']}）で原文を取得し、{'Message ID・説明・種別・カテゴリとフィールド表' if 'id' in e else '該当箇所'}を確認。抽出結果は data/raw/vendor/fortios_evidence.json"}
        if sid in S: S[sid].update(rec)
        else: src.append(rec); S[sid] = rec
    nec = [
        {"source_id": "SRC-NEC-IX2235-DL", "title": "UNIVERGE IX2235 プログラムファイル・ダウンロード", "publisher": "NEC Corporation",
         "url": "https://jpn.nec.com/univerge/ix/Download/ix2235/index.html", "document_type": "Vendor Download Page", "applicable_data": "IX2235 のソフトウェア版とイベントログリファレンス",
         "notes": "検索結果に表示された本文で、Ver 10.11.17（2026-04-24）などの掲載とイベントログリファレンスが ZIP（els/index.html）であることを確認。ページと ZIP は自動取得を 403 で拒否され、原文は未取得"},
        {"source_id": "SRC-NEC-IX-FAQ-LOG", "title": "UNIVERGE IXシリーズ FAQ ロギング、SYSLOGに関するFAQ", "publisher": "NEC Corporation",
         "url": "https://jpn.nec.com/univerge/ix/faq/els.html", "document_type": "Vendor FAQ", "applicable_data": "IX シリーズのロギング機能",
         "notes": "検索結果に表示された本文で、出力先（コンソール・SYSLOG サーバ・内部バッファ）、機能（ARP・IP・ICMP・PPP 等）とレベルの指定、ファシリティの既定値 local0(16) を確認。原文は未取得"},
    ]
    for n in nec:
        n.update(publication_date=None, last_updated=None, access_date=DAY, verification_status="一部確認", scope=["log_format"], reverified_v4=False,
                 verified_via="search_result", verified_url=n["url"], verified_date=DAY, verified_by="manual_review", verified_notes=n["notes"])
        if n["source_id"] in S: S[n["source_id"]].update(n)
        else: src.append(n); S[n["source_id"]] = n
    save("sources", src)


def vlog(ver, typ, sub, mid, msg, cli=False, notes=""):
    v = ver.replace(".", "")[:2]; page = f"FGT-{ver[:3]}-LOGREF-{mid}"
    ids = [ftnt_sid(page)] + ([ftnt_sid(f"FGT-{ver[:3]}-CLI-EXEC-LOG")] if cli else [])
    return {"vendor": "Fortinet", "product": "FortiGate (FortiOS)", "firmware_versions": [ver], "log_type": typ, "log_subtype": sub,
            "log_id": mid, "message": msg, "fields": FIELDS[mid], "cli_commands": CLI if cli else [], "source_ids": ids,
            "verification_status": "確認済み", "notes": notes or f"FortiOS {ver} の資料で確認。他の {ver[:3]}.x での同一性は未確認"}


def phase2_logs():
    logs = load("log_investigation"); L = by_id(logs)
    f = L["LOG-FORTIGATE-VENDOR"]
    tun = "7.6.3 以降は SSL VPN トンネルモード自体が IPsec VPN に置き換えられ GUI・CLI から削除された（リリースノート）。ログ参照には定義が残るが、7.6.3 以降に記録されるかは未確認"
    vl = []
    for ver in ("7.4.11", "7.6.7"):
        vl += [vlog(ver, "traffic", "forward", "13", "LOG_ID_TRAFFIC_END_FORWARD（Forward traffic）", cli=True),
               vlog(ver, "event", "system", "32002", "LOG_ID_ADMIN_LOGIN_FAIL（Admin login failed）")]
        if ver.startswith("7.4"): vl.append(vlog(ver, "event", "system", "32001", "LOG_ID_ADMIN_LOGIN_SUCC（Admin login successful）"))
        for mid, msg in (("39426", "LOG_ID_EVENT_SSL_VPN_USER_SSL_LOGIN_FAIL（SSL VPN login fail）"), ("39424", "LOG_ID_EVENT_SSL_VPN_USER_TUNNEL_UP（SSL VPN tunnel up）"),
                         ("39425", "LOG_ID_EVENT_SSL_VPN_USER_TUNNEL_DOWN（SSL VPN tunnel down）")):
            e = vlog(ver, "event", "vpn", mid, msg)
            if ver.startswith("7.6"): e["notes"] = tun; e["source_ids"].append(SSLVPN_763)
            vl.append(e)
        vl += [vlog(ver, "event", "vpn", "37138", "MESGID_CONN_UPDOWN（IPsec connection status changed）"),
               vlog(ver, "event", "vpn", "37139", "MESGID_P2_UPDOWN（IPsec phase 2 status changed）")]
    src74, src76 = ftnt_sid("FGT-7.4-LOGID-DEF"), ftnt_sid("FGT-7.6-LOGID-DEF")
    f.update(platform="FortiGate（FortiOS 7.4 / 7.6。版ごとに vendor_logs で区別）", vendor_logs=vl, log_sources=[
        {"channel": "Traffic ログ（type=traffic / subtype=forward）", "event_code": 13, "description": "LOG_ID_TRAFFIC_END_FORWARD（転送通信のセッション）"},
        {"channel": "Event ログ（type=event / subtype=system）", "event_code": 32002, "description": "LOG_ID_ADMIN_LOGIN_FAIL（管理者ログイン失敗）"},
        {"channel": "Event ログ（type=event / subtype=vpn）", "event_code": 39426, "description": "SSL VPN ログイン失敗（7.4。7.6.3 以降はトンネルモード廃止）"},
        {"channel": "Event ログ（type=event / subtype=vpn）", "event_code": 37138, "description": "MESGID_CONN_UPDOWN（IPsec 接続状態の変化）"}],
        common_fields=["srcip", "srcport", "dstip", "dstport", "proto", "action", "duration", "sentbyte", "rcvdbyte", "eventtime"],
        vendor_specific_fields=["vd", "policyid", "sessionid", "service", "app", "trandisp", "transip", "transport", "user", "group", "srcintf", "dstintf"],
        detection_analytics="境界の転送通信ログ（13）で action が拒否の宛先ポート別の急増、管理者ログイン失敗（32002）の連続、SSL VPN ログイン失敗（39426、7.4）の急増、IPsec 接続状態の変化（37138）を監視する。閾値は環境に合わせて決める。",
        investigation_procedure="1. `execute log filter device <device>` と `execute log filter category <category>` で対象のログを選ぶ\n2. `execute log filter field <name> <argument 1>` で srcip・dstip・dstport などを絞り込む\n3. `execute log display` で表示し、policyid・sessionid・action を確認する\n4. 管理者ログイン失敗（32002）は srcip・user・ui・reason、SSL VPN（39426）は remip・user・reason を確認する",
        unconfirmed_notes="action の取りうる値の一覧、logid フィールド（10 桁）の構成、device・category に指定する値、IPS などの UTM ログは未確認。版の記載は資料の版（7.4.11 / 7.6.7）で、他の版での同一性は未確認。",
        source_ids=sorted({s for e in vl for s in e["source_ids"]} | {src74, src76}), verified_date=DAY, certainty="一部確認")
    n = L["LOG-NECIX-VENDOR"]
    n.update(platform="NEC UNIVERGE IX2235", log_sources=[
        {"channel": "ロギング（コンソール・SYSLOG サーバ・内部バッファ）", "event_code": None, "description": "機能（ARP・IP・ICMP・PPP 等）とレベルを指定して出力（NEC FAQ。原文未取得）"}],
        common_fields=[], vendor_specific_fields=[],
        vendor_logs=[{"vendor": "NEC", "product": "UNIVERGE IX2235", "firmware_versions": ["10.11.17"], "log_type": "イベントログ",
                      "log_subtype": "", "log_id": "", "message": "", "fields": [], "cli_commands": [], "source_ids": ["SRC-NEC-IX2235-DL", "SRC-NEC-IX-FAQ-LOG"],
                      "verification_status": "未確認",
                      "notes": "メッセージは「機能名.番号」の形式（例: IP.006、MODM.010）で、ソフトウェア版ごとのイベントログリファレンス（ELS）に掲載される。ELS を取得できていないため個々のメッセージ・条件・取得方法は未収録"}],
        detection_analytics="未収録（IX2235 のイベントログリファレンスを取得できていないため、検知に使うメッセージを特定していない）。",
        investigation_procedure="1. 装置のソフトウェア版を確認する\n2. 同じ版のイベントログリファレンス（NEC の IX2235 ダウンロードページで配布）で、該当するメッセージ（機能名.番号）と出力条件を確認する",
        unconfirmed_notes="v1.1 までのフィールド（src-ip・dst-port・action: pass/block・ident/tag・filter-id 等）は公式資料で確認できないため削除。公式のイベントログリファレンスと FAQ の原文は自動取得を拒否され未取得（出典は検索結果の本文のみ）。",
        source_ids=["SRC-NEC-IX2235-DL", "SRC-NEC-IX-FAQ-LOG"], verified_date=DAY, certainty="未確認")
    save("log_investigation", logs)


# ================================================================ Phase 3: ログの関連付け（F-06・F-16）
GENERIC = {"Linux": ("LOG-LIN-GENERIC", "Linux（プラットフォーム共通）"), "macOS": ("LOG-MAC-GENERIC", "macOS（プラットフォーム共通）"),
           "ESXi": ("LOG-ESXI-GENERIC", "VMware ESXi（プラットフォーム共通）")}


def phase3_logs():
    """プラットフォーム共通ログを、データ内の ATT&CK analytic（公式 STIX）が参照するログ源から作る。ポートとは関連付けない。"""
    from collections import Counter
    logs = load("log_investigation"); L = by_id(logs); dets = load("detection_strategies")
    for pf, (lid, name) in GENERIC.items():
        an = [a for d in dets for a in d["analytics"] if pf in a["platforms"]]
        cnt = Counter(n for a in an for n in {x["name"] for x in a["log_sources"] if x["name"]})  # 参照する analytic の数
        chans = {}
        for a in an:
            for x in a["log_sources"]:
                ch = x["channel"] or ""
                if x["name"] and re.fullmatch(r"[\w./:=-]{1,30}", ch) and ch != "None": chans.setdefault(x["name"], Counter())[ch] += 1
        rec = {"id": lid, "platform": name,
               "log_sources": [{"channel": n, "event_code": None,
                                "description": f"ATT&CK analytic {c} 件が参照" + (f"（例: {', '.join(k for k, _ in chans[n].most_common(3))}）" if n in chans else "")}
                               for n, c in cnt.most_common(8)],
               "common_fields": [], "vendor_specific_fields": [],
               "detection_analytics": f"技術ごとの ATT&CK 検知戦略の analytic（{pf} 向け {len(an)} 件）を参照する。このログはプラットフォーム共通で、ポートに固有ではない。",
               "investigation_procedure": "1. ポート詳細の ATT&CK タブで技術の検知戦略（DET）を開く\n2. 対象プラットフォームの analytic が示すログ源とチャネルを確認する\n3. そのログ源で、通信の時刻・送信元・プロセスを突き合わせる",
               "unconfirmed_notes": "", "source_ids": ["SRC-MITRE-ATTACK"], "verified_date": DAY, "certainty": "確認済み",
               "analytics_ids": [], "port_scope": "platform", "ports": []}
        if lid in L: L[lid].update(rec)
        else: logs.append(rec); L[lid] = rec
    w = L["LOG-WIN-SECURITY"]  # F-16: any_windows は未実装だった。プラットフォーム共通として定義を直す
    w["port_scope"] = "platform"
    for x in logs:
        if x["port_scope"] == "any_windows": x["port_scope"] = "platform"
    save("log_investigation", logs)
    src = load("sources"); S = by_id(src); m = S["SRC-MITRE-ATTACK"]
    if "detection" not in m["scope"]: m["scope"].append("detection")  # ATT&CK は検知戦略・analytic を含む（v18 以降）
    save("sources", src)


# F-10: 攻撃手法ごとのポートとの関係。generic = どの公開サービスにも当てはまる / service_specific = 特定のサービスの機能に依存
GENERIC_ATK = {"ATK-BRUTE-FORCE", "ATK-VULN-SCAN", "ATK-PUBLIC-EXPLOIT", "ATK-REMOTE-EXPLOIT", "ATK-UNAUTH-SERVICE", "ATK-EXTERNAL-REMOTE",
               "ATK-C2-PORT", "ATK-EXFIL-ALT", "ATK-DATA-EXFIL", "ATK-TUNNEL", "ATK-AMPLIFICATION"}
REL = {"direct": "direct", "service": "inferred", "reference": "unverified"}
PTH_NOTE = ("T1550.002 の手順例で CrackMapExec が SMB で PtH の認証を行い、Wizard Spider・FIN13 が Invoke-SMBExec を使用。"
            "技術の説明と手順例にポート番号の記載はなく、445/tcp との対応は SMB の標準ポートによる推定")


def phase3_assoc():
    atk = load("attack_patterns"); A = by_id(atk)
    for a in atk: a["port_relation"] = "generic" if a["id"] in GENERIC_ATK else "service_specific"
    u = A["ATK-UNAUTH-SERVICE"]  # Default Accounts（T1078.001）は「認証のないサービス」と同じではない
    if "T1078.001" in u["technique_ids"]: u["technique_ids"].remove("T1078.001")
    save("attack_patterns", atk)
    ports = load("ports"); risks = load("port_risks"); R = by_id(risks); dropped = set()
    for p in ports:
        keep = []
        for b in p["technique_basis"]:
            if b["relation"] in ("attack_pattern", "generic", "inferred") and b["via"] and all(v.startswith("ATK-") for v in b["via"]):
                b["via"] = [v for v in b["via"] if b["technique"].split(".")[0] in {t.split(".")[0] for t in A[v]["technique_ids"]}]
                if not b["via"]: dropped.add(p["id"]); continue  # 根拠の攻撃手法から技術が外れた
                b["relation"] = "generic" if all(v in GENERIC_ATK for v in b["via"]) else "inferred"
            else: b["relation"] = REL.get(b["relation"], b["relation"])
            b["source_type"] = ("stix" if all(v.startswith("SRC-MITRE-") for v in b["via"]) else "document") if b["relation"] == "direct" else "curation"
            keep.append(b)
        p["technique_basis"] = keep
        lost = set(p["technique_ids"]) - {b["technique"] for b in keep}
        p["technique_ids"] = [t for t in p["technique_ids"] if t not in lost]
        for t in lost:
            r = R.get(p["risk_id"])
            if r and t in r["technique_ids"]: r["technique_ids"].remove(t)
    smb = next(p for p in ports if p["id"] == "PORT-00445-TCP")  # F-17
    if "ATK-PASS-THE-HASH" not in smb["attack_pattern_ids"]: smb["attack_pattern_ids"].append("ATK-PASS-THE-HASH")
    if "T1550.002" not in smb["technique_ids"]: smb["technique_ids"].append("T1550.002")
    if not any(b["technique"] == "T1550.002" for b in smb["technique_basis"]):
        smb["technique_basis"].append({"technique": "T1550.002", "relation": "inferred", "via": ["ATK-PASS-THE-HASH"], "note": PTH_NOTE, "source_type": "curation"})
    save("ports", ports); save("port_risks", risks)
    print("T1078.001 removed from", len(dropped), "ports")


PHASES = {"1": [phase1_sources, phase1_text, phase1_attacks, phase1_high, phase1_certainty, usage],
          "2": [phase2_sources, phase2_logs, usage],
          "3": [phase3_logs, phase3_assoc]}

if __name__ == "__main__":
    for ph in (sys.argv[1:] or sorted(PHASES)):
        for fn in PHASES[ph]: fn()
    print("applied:", ", ".join(sys.argv[1:] or sorted(PHASES)))

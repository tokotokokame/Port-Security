#!/usr/bin/env python3
"""One-off migration v3 -> v4. Kept for audit: every correction is explicit here.

Usage: python3 tools/migrate_v3_to_v4.py <v3_dir> <out_data_dir>
"""
import json, sys, copy
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from mitre_catalog import TECHNIQUES, DETECTION_STRATEGIES, DET0118, DET0463_DESC, DET_PAGES, VERIFIED

THREAT = {"attack_technique", "detection"}
NOTE_IANA_ONLY = "ポート番号・サービス名はIANAで確認済み。攻撃・検知記述に対応する一次資料は未付与(要追加)。"

# Port-level technique corrections (reason: T1003 = OS上の認証情報ダンプで、通信盗聴は対象外)
TECH_FIX = {
    "PORT-00020-TCP": {"T1003": ["T1040"]}, "PORT-00021-TCP": {"T1003": ["T1040"]},
    "PORT-00023-TCP": {"T1003": ["T1040"]}, "PORT-00069-UDP": {"T1003": ["T1552.001"]},
    "PORT-00088-TCP": {"T1003": ["T1558.003", "T1558.004"]}, "PORT-00088-UDP": {"T1003": ["T1558.003"]},
    "PORT-00110-TCP": {"T1003": ["T1040"]}, "PORT-00143-TCP": {"T1003": ["T1040"]},
    "PORT-00137-UDP": {"T1003": ["T1557.001"]}, "PORT-00389-TCP": {"T1003": ["T1040"]},
    "PORT-00587-TCP": {"T1003": []}, "PORT-01723-TCP": {"T1003": ["T1557", "T1110.002"]},
    "PORT-00500-UDP": {"T1003": ["T1110.002"]}, "PORT-05900-TCP": {"T1003": ["T1040"], "T1021": ["T1021.005"]},
    "PORT-05985-TCP": {"T1021": ["T1021.006"]}, "PORT-05986-TCP": {"T1021": ["T1021.006"]},
    "RISK-00023-TCP": {"T1003": ["T1040"]}, "RISK-05985-TCP": {"T1021": ["T1021.006"]},
    "ATK-CRED-THEFT": {"T1003": ["T1003", "T1040", "T1557.001", "T1558.003"]},
}
# Attack pattern -> logs, judged from each log record's own content
ATK_LOGS = {
    "ATK-BRUTE-FORCE": ["LOG-WIN-AN0327", "LOG-LIN-AN0328", "LOG-FORTIGATE-VENDOR", "LOG-NECIX-VENDOR"],
    "ATK-REMOTE-EXPLOIT": ["LOG-WIN-AN0327", "LOG-LIN-AN0328", "LOG-ESXI-AN0329", "LOG-MAC-AN0330"],
    "ATK-LATERAL-MOVE": ["LOG-WIN-AN0327"], "ATK-CRED-THEFT": ["LOG-WIN-AN0327"],
    "ATK-DATA-EXFIL": ["LOG-WIN-AN0327", "LOG-FORTIGATE-VENDOR"],
    "ATK-VULN-SCAN": ["LOG-FORTIGATE-VENDOR", "LOG-NECIX-VENDOR"],
    "ATK-RANSOMWARE": ["LOG-WIN-AN0327", "LOG-ESXI-AN0329"],
}
SRC_SCOPE = {"SRC-IANA-PORT": ["port_assignment"], "SRC-IANA-PROTO": ["protocol_assignment"],
             "SRC-MITRE-ATTACK": ["reference"], "SRC-MITRE-DET0118": ["detection"], "SRC-MS-RDS": ["service"],
             "SRC-CISA-HYGIENE": ["threat_guidance"], "SRC-FORTINET-DOCS": ["log_format"],
             "SRC-NEC-IX": ["log_format"], "SRC-IETF-RFC": ["port_assignment"]}
LOG_NOTES = {
    "LOG-WIN-AN0327": ("一部確認", "AN0327公式のログ源はSystem 1000/Sysmon 1,3,7,10,11,22。Security 4624/4625は本DB独自の追記。"),
    "LOG-LIN-AN0328": ("一部確認", "AN0328公式のログ源はsyslog/auditd/NSM Flow。auth.log/secureは本DB独自の追記。"),
    "LOG-ESXI-AN0329": ("一部確認", "AN0329公式のログ源はesxi:hostd(hostd.log/vmkernel.log/syslog.log)。vpxaは本DB独自の追記。"),
}

def load(d, f): return json.load(open(Path(d) / f, encoding="utf-8"))

def remap(rec, field):
    ids = [t for t in rec.pop("mitre_attack_ids", []) if not t.startswith("DET")]
    fix = TECH_FIX.get(rec["id"], {})
    out = []
    for t in ids:
        out += fix.get(t, [t])
    rec[field] = list(dict.fromkeys(out))

def official_ports(): return {p for a in DET0118["analytics"] if a[3] == "official" for p in a[2]}

def certify(rec, sources, allowed=THREAT, note=NOTE_IANA_ONLY):
    ok = any(sources[s]["reverified_v4"] and set(sources[s]["scope"]) & allowed for s in rec["source_ids"])
    if not ok:
        rec["certainty"] = "一部確認"
        rec["unconfirmed_notes"] = rec.get("unconfirmed_notes") or note

def build_sources(v3):
    out = []
    for s in v3:
        s = dict(s, scope=SRC_SCOPE[s["source_id"]], reverified_v4=s["source_id"] in ("SRC-IANA-PORT", "SRC-MITRE-DET0118"))
        out.append(s)
    def mitre(sid, title, url, upd):
        out.append({"source_id": sid, "title": title, "publisher": "The MITRE Corporation", "url": url,
                    "document_type": "MITRE ATT&CK", "applicable_data": title, "publication_date": None,
                    "last_updated": upd, "access_date": VERIFIED, "verification_status": "確認済み",
                    "notes": "v4で公式ページを直接確認", "scope": ["attack_technique", "detection"], "reverified_v4": True})
    for tid, t in TECHNIQUES.items():
        mitre(f"SRC-MITRE-{tid}", f"{tid} {t[0]}", f"https://attack.mitre.org/techniques/{tid}/", t[4])
    for det, d in DET_PAGES.items():
        mitre(f"SRC-MITRE-{det}", f"{det} {DETECTION_STRATEGIES[det][0]}",
              f"https://attack.mitre.org/detectionstrategies/{det}/", d)
    return out

def build_mitre():
    techs = [{"id": tid, "name": t[0], "tactics": t[1], "version": t[2], "created_date": t[3],
              "last_modified": t[4], "detection_strategy_ids": t[5],
              "subtechniques": [{"id": k, "name": v} for k, v in t[6].items()],
              "url": f"https://attack.mitre.org/techniques/{tid}/", "source_ids": [f"SRC-MITRE-{tid}"],
              "verified_date": VERIFIED, "certainty": "確認済み", "unconfirmed_notes": ""} for tid, t in TECHNIQUES.items()]
    dets = [{"id": "DET0118", "name": DET0118["name"], "technique_ids": ["T1210"], "version": DET0118["version"],
             "created_date": DET0118["created"], "last_modified": DET0118["last_modified"],
             "analytics": [{"id": a, "platform": pf, "monitored_ports": ports, "port_basis": basis,
                            "service_names": svc, "log_investigation_ids": [log]} for a, pf, ports, basis, svc, log in DET0118["analytics"]],
             "url": "https://attack.mitre.org/detectionstrategies/DET0118/", "source_ids": ["SRC-MITRE-DET0118"],
             "verified_date": VERIFIED, "certainty": "確認済み",
             "unconfirmed_notes": "AN0328の監視ポートは公式未記載。service_namesから標準ポートを推定(port_basis=inferred)。"}]
    for det, (name, tid, src, ans) in DETECTION_STRATEGIES.items():
        dets.append({"id": det, "name": name, "technique_ids": [tid], "version": None, "created_date": None,
                     "last_modified": None,
                     "analytics": [{"id": a, "platform": None, "description": DET0463_DESC.get(a), "monitored_ports": [],
                                    "port_basis": "none", "service_names": [], "log_investigation_ids": []} for a in ans],
                     "url": f"https://attack.mitre.org/detectionstrategies/{det}/", "source_ids": [src],
                     "verified_date": VERIFIED, "certainty": "一部確認",
                     "unconfirmed_notes": "名称・対象技術は公式ページで確認。analyticの対象プラットフォームとログ源は未収録。"})
    return techs, dets

PORT_427 = {
    "id": "PORT-00427-TCP", "port_number": 427, "protocol_number": 6, "transport_protocol": "TCP",
    "service_name": "svrloc", "formal_name": "Server Location (Service Location Protocol, SLP)",
    "purpose": "ネットワーク上のサービス発見(SLP)を行う。",
    "technical_description": "SLPによりクライアントがネットワーク上のサービスを検索・広告する。VMware ESXiではOpenSLP(slpd)として実装される。",
    "normal_usage_examples": "ESXi/CIM等のサービス発見",
    "malicious_exploitation_cases": "OpenSLPの未認証リモートコード実行脆弱性の悪用、侵入後のVM一括暗号化",
    "suspicious_traffic_features": "外部からの427/TCPアクセス, vmkernel.logでのslpdクラッシュ",
    "investigation_checkpoints": "ESXi hostd.log, vmkernel.log, NSM Flow 427接続",
    "recommended_defenses": "ESXi上のslpd停止, 外部からの427アクセス遮断",
    "attack_pattern_ids": ["ATK-REMOTE-EXPLOIT", "ATK-RANSOMWARE"], "mitre_attack_ids": ["T1210", "T1486"],
    "source_ids": ["SRC-IANA-PORT", "SRC-MITRE-DET0118"], "verified_date": VERIFIED, "certainty": "一部確認",
    "unconfirmed_notes": "v4でport_risks側の孤立レコードから新設。427/TCP=svrlocはIANAで確認、AN0329の監視対象。CVE-2021-21974/ESXiArgsの記述は個別出典未付与。",
}

def main(v3, out):
    P, S, PR, A, R, LG = (load(v3, f) for f in ["ports.json", "services.json", "protocols.json",
                                                 "attack_patterns.json", "port_risks.json", "log_investigation.json"])
    sources = build_sources(load(v3, "sources.json")); smap = {s["source_id"]: s for s in sources}
    techs, dets = build_mitre()
    P.append(copy.deepcopy(PORT_427))
    # 1) attack pattern <-> port: union of both directions, then single source of truth = ports
    key = lambda p: f"{p['port_number']}/{p['transport_protocol']}"
    pidx = {key(p): p for p in P}
    for a in A:
        for tp in a.pop("target_ports"):
            if tp in pidx and a["id"] not in pidx[tp]["attack_pattern_ids"]:
                pidx[tp]["attack_pattern_ids"].append(a["id"])
    off = official_ports()
    risk_of = {(r["port_number"], r["transport_protocol"]): r["id"] for r in R}
    srv_of = {s["port_number"]: s["id"] for s in S}
    for p in P:
        p.pop("source_urls", None)
        remap(p, "technique_ids")
        p["protocol_id"] = "PROTO-" + p["transport_protocol"]
        p["service_id"] = srv_of.get(p["port_number"])
        p["risk_id"] = risk_of.get((p["port_number"], p["transport_protocol"]))
        if p["port_number"] not in off and "SRC-MITRE-DET0118" in p["source_ids"]:
            p["source_ids"].remove("SRC-MITRE-DET0118")  # DET0118は公式監視ポートのみ根拠に数える
        if "SRC-IANA-PORT" not in p["source_ids"]:
            p["source_ids"].insert(0, "SRC-IANA-PORT")
        certify(p, smap)
    P.sort(key=lambda p: (p["port_number"], p["transport_protocol"]))
    for s in S:
        s.pop("source_urls", None); remap(s, "technique_ids"); certify(s, smap)
    for pr in PR:
        pr.pop("source_urls", None); remap(pr, "technique_ids")
        certify(pr, smap, note="プロトコル番号はIANAで確認済み。攻撃・検知記述に対応する一次資料は未付与(要追加)。")
    for a in A:
        a.pop("source_urls", None); remap(a, "technique_ids")
        for t in a["technique_ids"]:
            sid = f"SRC-MITRE-{t.split('.')[0]}"
            if sid not in a["source_ids"]: a["source_ids"].append(sid)
        a["log_investigation_ids"] = ATK_LOGS[a["id"]]
        certify(a, smap)
    for r in R:
        remap(r, "technique_ids"); certify(r, smap)
        if r["id"] == "RISK-00427-TCP":
            r["certainty"] = "一部確認"
            r["unconfirmed_notes"] = "DET0118/AN0329で427監視は確認。CVE-2021-21974/ESXiArgsの記述は個別出典未付与。"
    for l in LG:
        an = l["id"].split("-")[-1]
        l["analytics_ids"] = [an] if an.startswith("AN") else []
        l["port_scope"] = "analytics" if l["analytics_ids"] else "any"
        if l["id"] in LOG_NOTES:
            l["certainty"], l["unconfirmed_notes"] = LOG_NOTES[l["id"]]
        certify(l, smap, allowed={"detection", "log_format"}, note="ログ形式の一次資料が未確認。")
    out = Path(out); out.mkdir(parents=True, exist_ok=True)
    for name, data in [("ports", P), ("services", S), ("protocols", PR), ("attack_patterns", A),
                       ("port_risks", R), ("log_investigation", LG), ("mitre_techniques", techs),
                       ("detection_strategies", dets), ("sources", sources)]:
        (out / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"written to {out}")

if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])

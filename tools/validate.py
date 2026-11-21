#!/usr/bin/env python3
"""Integrity validator for the Port-Security database (stdlib only).

Usage: python3 tools/validate.py [data_dir]   -> exit 1 on any error
"""
import json, re, sys
from pathlib import Path

FILES = ["ports", "services", "protocols", "attack_patterns", "port_risks", "log_investigation",
         "mitre_techniques", "detection_strategies", "mitre_software", "tools", "vulnerabilities", "sources"]
COMMON = ["id", "source_ids", "verified_date", "certainty", "unconfirmed_notes"]
REQUIRED = {
    "ports": COMMON + ["port_number", "transport_protocol", "service_name", "category", "protocol_id", "service_id", "risk_id",
                       "malicious_exploitation_cases", "suspicious_traffic_features", "investigation_checkpoints",
                       "recommended_defenses", "attack_pattern_ids", "technique_ids"],
    "services": COMMON + ["port_number", "service_name", "attack_pattern_ids", "technique_ids"],
    "protocols": COMMON + ["protocol_number", "technique_ids", "attack_pattern_ids"],
    "attack_patterns": COMMON + ["attack_name", "detection_methods", "technique_ids", "log_investigation_ids"],
    "port_risks": COMMON + ["port_number", "transport_protocol", "risk_level", "technique_ids"],
    "log_investigation": COMMON + ["platform", "log_sources", "analytics_ids", "port_scope", "ports", "investigation_procedure"],
    "mitre_techniques": COMMON + ["name", "tactics", "detection_strategy_ids", "subtechniques", "url"],
    "detection_strategies": COMMON + ["name", "technique_ids", "analytics", "url"],
    "mitre_software": COMMON + ["name", "technique_ids", "url"],
    "tools": COMMON + ["name", "category", "mitre_software_id", "ports", "artifacts", "detection", "attack_pattern_ids",
                       "technique_ids", "log_investigation_ids"],
    "vulnerabilities": COMMON + ["affected", "cvss", "kev", "risk_ids", "condition", "raw"],
    "sources": ["source_id", "title", "url", "scope", "reverified_v4", "verification_status"],
}
ID_RE = {"ports": r"PORT-\d{5}-(TCP|UDP|SCTP)", "services": r"SRV-[A-Z0-9-]+", "protocols": r"PROTO-[A-Z0-9]+",
         "attack_patterns": r"ATK-[A-Z0-9-]+", "port_risks": r"RISK-\d{5}-(TCP|UDP|SCTP)", "log_investigation": r"LOG-[A-Z0-9-]+",
         "mitre_techniques": r"T\d{4}", "detection_strategies": r"DET\d{4}", "mitre_software": r"S\d{4}",
         "tools": r"TOOL-[A-Z0-9-]+", "vulnerabilities": r"CVE-\d{4}-\d{4,7}", "sources": r"SRC-[A-Z0-9-]+"}
CERTAINTY = {"確認済み", "一部確認", "未確認"}
THREAT = {"attack_technique", "detection", "threat_advisory"}
NEEDS = {"log_investigation": {"detection", "log_format"}, "vulnerabilities": {"vulnerability"}}
SCOPES = {"analytics", "any", "any_windows", "listed"}


def load_all(d):
    return {f: json.load(open(Path(d) / f"{f}.json", encoding="utf-8")) for f in FILES}


def validate(db):
    E, W = [], []
    rid = lambda r: r.get("id") or r.get("source_id")
    idx = {f: {rid(r): r for r in db[f]} for f in FILES}
    seen = {}
    for f in FILES:
        for r in db[f]:
            i = rid(r)
            E += [f"{f}:{i}: 必須フィールド欠落 '{k}'" for k in REQUIRED[f] if k not in r]
            if not re.fullmatch(ID_RE[f], str(i)): E.append(f"{f}:{i}: ID形式不正")
            if i in seen: E.append(f"{f}:{i}: ID重複 ({seen[i]})")
            seen[i] = f
    if E: return E, W
    subs = {s["id"]: t["id"] for t in db["mitre_techniques"] for s in t["subtechniques"]}
    tech_ok = set(idx["mitre_techniques"]) | set(subs)
    port_keys = {(p["port_number"], p["transport_protocol"]) for p in db["ports"]}
    det0118 = idx["detection_strategies"].get("DET0118", {"analytics": []})
    det0118_ports = {tuple(p) for a in det0118["analytics"] if a["port_basis"] == "official" for p in a["monitored_ports"]}

    def fk(where, field, target, vals):
        for v in vals if isinstance(vals, list) else [vals]:
            if v is not None and v not in idx[target]: E.append(f"{where}: {field} 参照切れ -> {v}")

    for f in FILES:
        if f == "sources": continue
        for r in db[f]:
            w = f"{f}:{r['id']}"
            fk(w, "source_ids", "sources", r["source_ids"])
            fk(w, "attack_pattern_ids", "attack_patterns", r.get("attack_pattern_ids", []))
            for t in r.get("technique_ids", []):
                if t.startswith("DET"): E.append(f"{w}: technique_ids に検知戦略ID混入 -> {t}")
                elif t not in tech_ok: E.append(f"{w}: technique_ids 未収録 -> {t}")
            if r["certainty"] not in CERTAINTY: E.append(f"{w}: certainty 値不正")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r["verified_date"])): E.append(f"{w}: verified_date 形式不正")
            if r["certainty"] != "確認済み" and not r["unconfirmed_notes"]: E.append(f"{w}: 確認済み以外なのに unconfirmed_notes が空")
            need = NEEDS.get(f, THREAT)
            if r["certainty"] == "確認済み" and not any(
                    idx["sources"].get(s, {}).get("reverified_v4") and set(idx["sources"][s]["scope"]) & need for s in r["source_ids"]):
                E.append(f"{w}: 確認済みだが再検証済みの根拠資料(scope={sorted(need)})がない")
    for p in db["ports"]:
        w = f"ports:{p['id']}"
        if p["id"] != f"PORT-{p['port_number']:05d}-{p['transport_protocol']}": E.append(f"{w}: IDとポート/通信方式が不一致")
        fk(w, "protocol_id", "protocols", p["protocol_id"]); fk(w, "service_id", "services", p["service_id"])
        fk(w, "risk_id", "port_risks", p["risk_id"])
        s = idx["services"].get(p["service_id"])
        if s and [p["port_number"], p["transport_protocol"]] not in s["ports"]: E.append(f"{w}: service_id の (番号, 通信方式) 不一致")
        if "SRC-MITRE-DET0118" in p["source_ids"] and (p["port_number"], p["transport_protocol"]) not in det0118_ports:
            E.append(f"{w}: DET0118の公式監視ポート外なのに根拠に引用")
        if not p["technique_ids"]: W.append(f"{w}: technique_ids が空")
        for e in p.get("evidence", []):
            fk(w, "evidence.source_id", "sources", e["source_id"])
            if e["source_id"] not in p["source_ids"]: E.append(f"{w}: evidence の出典が source_ids にない -> {e['source_id']}")
    by_port = {(p["port_number"], p["transport_protocol"]): p for p in db["ports"]}
    for r in db["port_risks"]:
        p = by_port.get((r["port_number"], r["transport_protocol"]))
        if not p: E.append(f"port_risks:{r['id']}: 対応するポートレコードなし(孤立)")
        elif p["risk_id"] != r["id"]: E.append(f"port_risks:{r['id']}: ports側の risk_id と不一致")
    for s in db["services"]:
        refs = sorted([p["port_number"], p["transport_protocol"]] for p in db["ports"] if p["service_id"] == s["id"])
        if not refs: E.append(f"services:{s['id']}: どのポートからも参照されない")
        elif sorted(s["ports"]) != refs: E.append(f"services:{s['id']}: ports が参照元ポート {refs} と不一致")
    for a in db["attack_patterns"]:
        fk(f"attack_patterns:{a['id']}", "log_investigation_ids", "log_investigation", a["log_investigation_ids"])
    for t in db["tools"]:
        w = f"tools:{t['id']}"
        fk(w, "log_investigation_ids", "log_investigation", t["log_investigation_ids"])
        fk(w, "mitre_software_id", "mitre_software", t["mitre_software_id"])
        E += [f"{w}: ports にない番号 -> {n}/{tp}" for n, tp in t["ports"] if (n, tp) not in port_keys]
        if not t["mitre_software_id"] and not t["technique_ids"]: E.append(f"{w}: ATT&CK 未収録ツールは technique_ids 必須")
    for v in db["vulnerabilities"]:
        w = f"vulnerabilities:{v['id']}"
        fk(w, "risk_ids", "port_risks", v["risk_ids"]); fk(w, "service_ids", "services", v.get("service_ids", []))
    dets = idx["detection_strategies"]
    for t in db["mitre_techniques"]:
        for x in [t] + t["subtechniques"]:
            for d in x["detection_strategy_ids"]:
                if d not in dets: E.append(f"mitre_techniques:{x['id']}: 検知戦略 参照切れ -> {d}")
                elif x["id"] not in dets[d]["technique_ids"]: E.append(f"mitre_techniques:{x['id']}: {d} 側に逆参照がない")
    an_logs = {}
    for d in db["detection_strategies"]:
        E += [f"detection_strategies:{d['id']}: technique_ids 未収録 -> {t}" for t in d["technique_ids"] if t not in tech_ok]
        for a in d["analytics"]:
            if a["port_basis"] not in {"official", "inferred", "none"}: E.append(f"{d['id']}/{a['id']}: port_basis 値不正")
            if a["transport_basis"] not in {"stated", "service_default", "none"}: E.append(f"{d['id']}/{a['id']}: transport_basis 値不正")
            if bool(a["monitored_ports"]) == (a["transport_basis"] == "none"): E.append(f"{d['id']}/{a['id']}: 監視ポートと transport_basis が矛盾")
            fk(f"{d['id']}/{a['id']}", "log_investigation_ids", "log_investigation", a["log_investigation_ids"])
            an_logs[a["id"]] = set(a["log_investigation_ids"])
    for l in db["log_investigation"]:
        w = f"log_investigation:{l['id']}"
        E += [f"{w}: {an} 側にこのログへの参照がない" for an in l["analytics_ids"] if l["id"] not in an_logs.get(an, set())]
        if l["port_scope"] not in SCOPES: E.append(f"{w}: port_scope 値不正")
        if l["port_scope"] == "listed" and not l["ports"]: E.append(f"{w}: listed なのに ports が空")
        E += [f"{w}: ports にない番号 -> {n}/{tp}" for n, tp in l["ports"] if (n, tp) not in port_keys]
    return E, W


if __name__ == "__main__":
    db = load_all(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "data")
    errors, warnings = validate(db)
    for w in warnings: print("WARN ", w)
    for e in errors: print("ERROR", e)
    print(f"\n{sum(len(v) for v in db.values())} records / errors={len(errors)} warnings={len(warnings)} -> {'FAIL' if errors else 'PASS'}")
    sys.exit(1 if errors else 0)

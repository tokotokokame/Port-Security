#!/usr/bin/env python3
"""Integrity validator for the Port-Security database (stdlib only).

Usage: python3 tools/validate.py [data_dir]   -> exit 1 on any error
"""
import json, re, sys
from pathlib import Path

FILES = ["ports", "services", "protocols", "attack_patterns", "port_risks",
         "log_investigation", "mitre_techniques", "detection_strategies", "sources"]
COMMON = ["id", "source_ids", "verified_date", "certainty", "unconfirmed_notes"]
REQUIRED = {
    "ports": COMMON + ["port_number", "transport_protocol", "service_name", "protocol_id", "service_id", "risk_id",
                       "malicious_exploitation_cases", "suspicious_traffic_features", "investigation_checkpoints",
                       "recommended_defenses", "attack_pattern_ids", "technique_ids"],
    "services": COMMON + ["port_number", "service_name", "attack_pattern_ids", "technique_ids"],
    "protocols": COMMON + ["protocol_number", "technique_ids", "attack_pattern_ids"],
    "attack_patterns": COMMON + ["attack_name", "detection_methods", "technique_ids", "log_investigation_ids"],
    "port_risks": COMMON + ["port_number", "transport_protocol", "risk_level", "technique_ids"],
    "log_investigation": COMMON + ["platform", "log_sources", "analytics_ids", "port_scope", "investigation_procedure"],
    "mitre_techniques": COMMON + ["name", "tactics", "detection_strategy_ids", "subtechniques", "url"],
    "detection_strategies": COMMON + ["name", "technique_ids", "analytics", "url"],
    "sources": ["source_id", "title", "url", "scope", "reverified_v4", "verification_status"],
}
ID_RE = {"ports": r"PORT-\d{5}-(TCP|UDP|SCTP)", "services": r"SRV-[A-Z0-9-]+", "protocols": r"PROTO-[A-Z0-9]+",
         "attack_patterns": r"ATK-[A-Z0-9-]+", "port_risks": r"RISK-\d{5}-(TCP|UDP|SCTP)", "log_investigation": r"LOG-[A-Z0-9-]+",
         "mitre_techniques": r"T\d{4}", "detection_strategies": r"DET\d{4}", "sources": r"SRC-[A-Z0-9-]+"}
CERTAINTY = {"確認済み", "一部確認", "未確認"}
NEEDS = {"log_investigation": {"detection", "log_format"}}  # default: attack_technique / detection
THREAT = {"attack_technique", "detection"}


def load_all(d):
    return {f: json.load(open(Path(d) / f"{f}.json", encoding="utf-8")) for f in FILES}


def validate(db):
    E, W = [], []
    idx = {f: {(r.get("id") or r.get("source_id")): r for r in db[f]} for f in FILES}
    seen = {}
    for f in FILES:
        for r in db[f]:
            rid = r.get("id") or r.get("source_id")
            for k in REQUIRED[f]:
                if k not in r: E.append(f"{f}:{rid}: 必須フィールド欠落 '{k}'")
            if not re.fullmatch(ID_RE[f], str(rid)): E.append(f"{f}:{rid}: ID形式不正")
            if rid in seen: E.append(f"{f}:{rid}: ID重複 ({seen[rid]})")
            seen[rid] = f
    tech_ok = set(idx["mitre_techniques"]) | {s["id"] for t in db["mitre_techniques"] for s in t["subtechniques"]}
    det0118 = idx["detection_strategies"].get("DET0118", {"analytics": []})
    det0118_ports = {p for a in det0118["analytics"] if a["port_basis"] == "official" for p in a["monitored_ports"]}

    def fk(f, rid, field, target, vals):
        for v in vals if isinstance(vals, list) else [vals]:
            if v is not None and v not in idx[target]: E.append(f"{f}:{rid}: {field} 参照切れ -> {v}")

    for f in FILES:
        if f == "sources": continue
        for r in db[f]:
            rid = r["id"]
            fk(f, rid, "source_ids", "sources", r["source_ids"])
            for k in ("attack_pattern_ids",): fk(f, rid, k, "attack_patterns", r.get(k, []))
            for t in r.get("technique_ids", []):
                if t.startswith("DET"): E.append(f"{f}:{rid}: technique_ids に検知戦略ID混入 -> {t}")
                elif t not in tech_ok: E.append(f"{f}:{rid}: technique_ids 未収録 -> {t}")
            if r["certainty"] not in CERTAINTY: E.append(f"{f}:{rid}: certainty 値不正")
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", str(r["verified_date"])): E.append(f"{f}:{rid}: verified_date 形式不正")
            if r["certainty"] != "確認済み" and not r["unconfirmed_notes"]:
                E.append(f"{f}:{rid}: 確認済み以外なのに unconfirmed_notes が空")
            need = NEEDS.get(f, THREAT)
            if r["certainty"] == "確認済み" and not any(
                    idx["sources"].get(s, {}).get("reverified_v4") and set(idx["sources"][s]["scope"]) & need
                    for s in r["source_ids"]):
                E.append(f"{f}:{rid}: 確認済みだが再検証済みの根拠資料(scope={sorted(need)})がない")
    for p in db["ports"]:
        rid = p["id"]
        if rid != f"PORT-{p['port_number']:05d}-{p['transport_protocol']}": E.append(f"ports:{rid}: IDとポート/通信方式が不一致")
        fk("ports", rid, "protocol_id", "protocols", p["protocol_id"])
        fk("ports", rid, "service_id", "services", p["service_id"])
        fk("ports", rid, "risk_id", "port_risks", p["risk_id"])
        s = idx["services"].get(p["service_id"])
        if s and s["port_number"] != p["port_number"]: E.append(f"ports:{rid}: service_id のポート番号不一致")
        if "SRC-MITRE-DET0118" in p["source_ids"] and p["port_number"] not in det0118_ports:
            E.append(f"ports:{rid}: DET0118の公式監視ポート外なのに根拠に引用")
        if not p["technique_ids"]: W.append(f"ports:{rid}: technique_ids が空")
    by_port = {(p["port_number"], p["transport_protocol"]): p for p in db["ports"]}
    for r in db["port_risks"]:
        p = by_port.get((r["port_number"], r["transport_protocol"]))
        if not p: E.append(f"port_risks:{r['id']}: 対応するポートレコードなし(孤立)")
        elif p["risk_id"] != r["id"]: E.append(f"port_risks:{r['id']}: ports側の risk_id と不一致")
    for s in db["services"]:
        if not any(p["service_id"] == s["id"] for p in db["ports"]): E.append(f"services:{s['id']}: どのポートからも参照されない")
    for a in db["attack_patterns"]:
        fk("attack_patterns", a["id"], "log_investigation_ids", "log_investigation", a["log_investigation_ids"])
    for t in db["mitre_techniques"]:
        fk("mitre_techniques", t["id"], "detection_strategy_ids", "detection_strategies", t["detection_strategy_ids"])
        for d in t["detection_strategy_ids"]:
            if d in idx["detection_strategies"] and t["id"] not in idx["detection_strategies"][d]["technique_ids"]:
                E.append(f"mitre_techniques:{t['id']}: {d} 側に逆参照がない")
    an_logs = {}
    for d in db["detection_strategies"]:
        fk("detection_strategies", d["id"], "technique_ids", "mitre_techniques", d["technique_ids"])
        for a in d["analytics"]:
            if a["port_basis"] not in {"official", "inferred", "none"}: E.append(f"{d['id']}/{a['id']}: port_basis 値不正")
            fk("detection_strategies", f"{d['id']}/{a['id']}", "log_investigation_ids", "log_investigation", a["log_investigation_ids"])
            an_logs[a["id"]] = set(a["log_investigation_ids"])
    for l in db["log_investigation"]:
        for an in l["analytics_ids"]:
            if l["id"] not in an_logs.get(an, set()): E.append(f"log_investigation:{l['id']}: {an} との双方向リンク不一致")
        if l["port_scope"] not in {"analytics", "any"}: E.append(f"log_investigation:{l['id']}: port_scope 値不正")
    return E, W


if __name__ == "__main__":
    db = load_all(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent.parent / "data")
    errors, warnings = validate(db)
    for w in warnings: print("WARN ", w)
    for e in errors: print("ERROR", e)
    n = sum(len(v) for v in db.values())
    print(f"\n{n} records / errors={len(errors)} warnings={len(warnings)} -> {'FAIL' if errors else 'PASS'}")
    sys.exit(1 if errors else 0)

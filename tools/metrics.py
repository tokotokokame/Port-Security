#!/usr/bin/env python3
"""VALIDATION_REPORT 用の指標（修正指示書 9 章）。前回値（docs/metrics/v1.1.json）との差分を出す。

Usage: python3 tools/metrics.py [--freeze docs/metrics/v1.1.json]   (--freeze は基準値の保存。通常は build_index.py から呼ぶ)
"""
import json, sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).parent.parent
CERT = ["確認済み", "一部確認", "未確認"]
REL = {"direct": "direct", "generic": "generic", "inferred": "inferred", "unverified": "unverified",
       "attack_pattern": "attack_pattern(v1.1)", "service": "service(v1.1)", "reference": "reference(v1.1)"}
CLS = {0: "B", 1: "A", 2: "B", 3: "B'", 4: "C/D", 5: "C/D"}


def compute(db, ports_dist, catalog=None):
    m = {}
    recs = [r for f, v in db.items() if f != "sources" for r in v]
    m["データ: レコード総数"] = len(recs) + len(db["sources"])
    c = Counter(r.get("certainty") for r in recs)
    for k in CERT: m[f"データ: {k}"] = c.get(k, 0)
    m["データ: 出典なし（source_ids が空）"] = sum(1 for f, v in db.items() if f not in ("sources", "mitre_techniques", "mitre_software", "detection_strategies")
                                       for r in v if not r.get("source_ids"))
    m["データ: 確認方法が未記録の出典"] = sum(1 for s in db["sources"] if s.get("verified_via") not in
                                    ("original_document", "official_api", "official_stix", "official_repository", "search_result", "not_verified"))
    sc = Counter(s["verification_status"] for s in db["sources"])
    for k in CERT: m[f"出典: {k}"] = sc.get(k, 0)
    best = Counter()
    for p in ports_dist:
        ranks = [l["rank"] for l in p["logs"]]
        cls = {CLS[r] for r in ranks}
        best[next((k for k in ("A", "B", "B'", "C/D") if k in cls), "なし")] += 1
    for k in ("A", "B", "B'", "C/D"): m[f"ログ: {k}"] = best.get(k, 0)
    m["ログ: ポート固有ログなし（A・B なし）"] = sum(1 for p in ports_dist if not {CLS[l["rank"]] for l in p["logs"]} & {"A", "B"})
    rl = Counter(r["risk_level"] for r in db["port_risks"])
    for k in ("Critical", "High", "Medium", "Low"): m[f"リスク: {k}"] = rl.get(k, 0)
    m["リスク: service_risk 未設定"] = sum(1 for r in db["port_risks"] if "service_risk" not in r)
    m["リスク: service_risk 未評価（根拠なし）"] = sum(1 for r in db["port_risks"] if r.get("service_risk", {}).get("level") == "未評価")
    m["リスク: exposure_condition 未設定"] = sum(1 for r in db["port_risks"] if "exposure_condition" not in r)
    if catalog:
        known = set(catalog["techniques"])
        m["ATT&CK: 公式に存在しない／廃止の ID"] = sum(1 for f in ("ports", "services", "protocols", "attack_patterns", "port_risks", "tools")
                                         for r in db[f] for t in r.get("technique_ids", [])
                                         if t not in known or catalog["techniques"][t]["revoked"] or catalog["techniques"][t]["deprecated"])
    uses = {s["id"]: set(s["technique_ids"]) for s in db["mitre_software"]}
    m["ATT&CK: ツールの公式 uses 関係にない技術"] = sum(len(set(t["technique_ids"]) - uses.get(t["mitre_software_id"], set()))
                                          for t in db["tools"] if t.get("mitre_software_id"))
    rel = Counter(REL.get(b["relation"], b["relation"]) for p in db["ports"] for b in p["technique_basis"])
    for k in sorted(rel): m[f"ATT&CK 関連: {k}"] = rel[k]
    return m


def table(now, base):
    rows = ["| 指標 | v1.1 | v1.2 | 差分 |", "|---|---:|---:|---:|"]
    for k in list(dict.fromkeys(list(base) + list(now))):
        a, b = base.get(k), now.get(k)
        d = "" if a is None or b is None else f"{b - a:+d}"
        rows.append(f"| {k} | {'—' if a is None else a} | {'—' if b is None else b} | {d} |")
    return rows


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent)); from validate import load_all
    db = load_all(ROOT / "data"); ports = json.loads((ROOT / "dist/ports.json").read_text(encoding="utf-8"))
    cat = json.loads((ROOT / "data/raw/mitre/attack_catalog.json").read_text(encoding="utf-8"))
    m = compute(db, ports, cat)
    if "--freeze" in sys.argv:
        out = ROOT / sys.argv[sys.argv.index("--freeze") + 1]; out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(m, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
    print(json.dumps(m, ensure_ascii=False, indent=1))

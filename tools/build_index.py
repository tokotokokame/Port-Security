#!/usr/bin/env python3
"""Build app/dist assets and docs/VALIDATION_REPORT.md (fails if validation fails).

Outputs (same content in dist/ and app/assets/data/):
  ports.json  detailed ports with ID references and log relevance
  kb.json     attacks, techniques, detection strategies, tools, logs, sources
  iana.json   every IANA-registered port: [port, transport, names, description, unauthorized-use note]
"""
import csv, json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))
from validate import load_all, validate

ROOT = Path(__file__).parent.parent
MATCH = ["DET公式監視ポート一致", "公式文書のポート指定", "DETサービス名から推定", "ATT&CK検知戦略(プラットフォーム)",
         "攻撃手法・ツール経由", "境界機器ログ(全ポート共通)"]


def build(db):
    ix = {f: {(r.get("id") or r.get("source_id")): r for r in db[f]} for f in db}
    parent = {s["id"]: t for t in db["mitre_techniques"] for s in t["subtechniques"]}
    det_of = {t["id"]: t["detection_strategy_ids"] for t in db["mitre_techniques"]}
    det_of.update({s["id"]: s["detection_strategy_ids"] for t in db["mitre_techniques"] for s in t["subtechniques"]})
    soft_tech = {s["id"]: s["technique_ids"] for s in db["mitre_software"]}
    tool_techs = {t["id"]: sorted(set(t["technique_ids"]) | set(soft_tech.get(t["mitre_software_id"], []))) for t in db["tools"]}
    tools_at = {}
    for t in db["tools"]:
        for n, tp in t["ports"]: tools_at.setdefault((n, tp), []).append(t["id"])
    ports = []
    for p in db["ports"]:
        key, logs, rank = (p["port_number"], p["transport_protocol"]), {}, {}
        def add(lid, via, lv):
            logs.setdefault(lid, set()).add(via); rank[lid] = min(rank.get(lid, 9), lv)
        for d in db["detection_strategies"]:
            for a in d["analytics"]:
                if p["port_number"] in a["monitored_ports"]:
                    for lid in a["log_investigation_ids"]: add(lid, f"{d['id']}/{a['id']}", 0 if a["port_basis"] == "official" else 2)
        for l in db["log_investigation"]:
            if l["port_scope"] == "listed" and list(key) in [list(x) for x in l["ports"]]: add(l["id"], "公式文書のポート指定", 1)
            if l["port_scope"] == "any": add(l["id"], "境界機器ログ(全ポート共通)", 5)
        for t in p["technique_ids"]:
            for did in det_of.get(t, []):
                for a in ix["detection_strategies"][did]["analytics"]:
                    for lid in a["log_investigation_ids"]: add(lid, f"{did}/{a['id']}", 3)
        tools = tools_at.get(key, [])
        for aid in p["attack_pattern_ids"]:
            for lid in ix["attack_patterns"][aid]["log_investigation_ids"]: add(lid, aid, 4)
        for tid in tools:
            for lid in ix["tools"][tid]["log_investigation_ids"]: add(lid, tid, 4)
        risk = ix["port_risks"].get(p["risk_id"])
        gaps = []
        if p["certainty"] != "確認済み": gaps.append("攻撃・検知記述の一次資料未付与")
        if min(rank.values(), default=9) > 3: gaps.append("ポートに対応するホストログなし")
        if not risk: gaps.append("リスク評価なし")
        ports.append({
            "id": p["id"], "n": p["port_number"], "t": p["transport_protocol"], "service": p["service_name"],
            "name": p["formal_name"], "iana": p.get("iana_description", ""), "category": p["category"],
            "purpose": p["purpose"], "technical": p.get("technical_description", ""), "normal": p.get("normal_usage_examples", ""),
            "malicious": p["malicious_exploitation_cases"], "suspicious": p["suspicious_traffic_features"],
            "checkpoints": p["investigation_checkpoints"], "defenses": p["recommended_defenses"],
            "certainty": p["certainty"], "notes": p["unconfirmed_notes"], "verified": p["verified_date"],
            "risk": None if not risk else {"level": risk["risk_level"], "reason": risk["reason_targeted"],
                                           "indicators": risk.get("suspicious_indicators", ""), "focus": risk.get("investigation_focus", ""),
                                           "mitigation": risk.get("mitigation_controls", ""), "certainty": risk["certainty"]},
            "attacks": p["attack_pattern_ids"], "techniques": p["technique_ids"], "tools": tools,
            "logs": [{"id": l, "match": MATCH[rank[l]], "rank": rank[l], "via": sorted(v)} for l, v in sorted(logs.items(), key=lambda kv: (rank[kv[0]], kv[0]))],
            "sources": list(dict.fromkeys(p["source_ids"] + (risk or {}).get("source_ids", []) +
                                          [f"SRC-MITRE-{t.split('.')[0]}" for t in p["technique_ids"]])),
            "gaps": gaps})
    techniques = {}
    for t in db["mitre_techniques"]:
        techniques[t["id"]] = {"name": t["name"], "tactics": t["tactics"], "url": t["url"], "parent": None, "dets": t["detection_strategy_ids"]}
        for s in t["subtechniques"]:
            techniques[s["id"]] = {"name": s["name"], "tactics": t["tactics"], "parent": t["id"], "dets": s["detection_strategy_ids"],
                                   "url": "https://attack.mitre.org/techniques/" + s["id"].replace(".", "/") + "/"}
    kb = {
        "attacks": {a["id"]: {"name": a["attack_name"], "category": a.get("category", ""), "description": a.get("description", ""),
                              "features": a.get("attack_features", ""), "detection": a["detection_methods"],
                              "defenses": a.get("recommended_defenses", ""), "techniques": a["technique_ids"],
                              "logs": a["log_investigation_ids"], "sources": a["source_ids"]} for a in db["attack_patterns"]},
        "techniques": techniques,
        "dets": {d["id"]: {"name": d["name"], "url": d["url"], "analytics": [
            {"id": a["id"], "platforms": a["platforms"], "description": a["description"],
             "logs": [[x["name"], x["channel"]] for x in a["log_sources"]]} for a in d["analytics"]]} for d in db["detection_strategies"]},
        "tools": {t["id"]: {"name": t["name"], "category": t["category"], "sid": t["mitre_software_id"], "summary": t["summary"],
                            "ports": t["ports"], "artifacts": t["artifacts"], "detection": t["detection"], "attacks": t["attack_pattern_ids"],
                            "techniques": tool_techs[t["id"]], "logs": t["log_investigation_ids"], "sources": t["source_ids"],
                            "certainty": t["certainty"], "notes": t["unconfirmed_notes"]} for t in db["tools"]},
        "logs": {l["id"]: {"platform": l["platform"], "sources": [[s["channel"], s["event_code"], s["description"]] for s in l["log_sources"]],
                           "analytics": l.get("detection_analytics", ""), "procedure": l["investigation_procedure"],
                           "certainty": l["certainty"], "notes": l["unconfirmed_notes"], "refs": l["source_ids"]} for l in db["log_investigation"]},
        "sources": {s["source_id"]: {"title": s["title"], "url": s["url"], "publisher": s.get("publisher", ""),
                                     "scope": s["scope"], "verified": s["reverified_v4"]} for s in db["sources"]},
        "software": {s["id"]: {"name": s["name"], "description": s["description"], "url": s["url"]} for s in db["mitre_software"]},
    }
    return ports, kb


def iana_rows():
    rows = {}
    for r in csv.DictReader(open(ROOT / "data/raw/iana/service-names-port-numbers.csv", encoding="utf-8", newline="")):
        name, num, tp = r["Service Name"].strip(), r["Port Number"].strip(), r["Transport Protocol"].upper()
        if not name or not num or tp not in ("TCP", "UDP", "SCTP", "DCCP"): continue
        lo, _, hi = num.partition("-")
        for n in range(int(lo), int(hi or lo) + 1):
            e = rows.setdefault((n, tp), [n, tp, [], r["Description"].strip(), r["Unauthorized Use Reported"].strip()])
            if name not in e[2]: e[2].append(name)
    return [[n, tp, " / ".join(names), d, u] for (n, tp), (_, _, names, d, u) in sorted(rows.items())]


def report(db, ports, iana, errors, warnings):
    n = len(ports); pct = lambda k: f"{k}/{n} ({k * 100 // n}%)"
    cnt = lambda pred: pct(sum(1 for r in ports if pred(r)))
    latest = max(r["verified_date"] for f, v in db.items() if f != "sources" for r in v)
    rows = [("攻撃手法あり", cnt(lambda r: r["attacks"])), ("MITRE技術あり", cnt(lambda r: r["techniques"])),
            ("攻撃ツールの紐付けあり", cnt(lambda r: r["tools"])),
            ("ホストログ(DET監視ポート・公式文書・推定・検知戦略)", cnt(lambda r: any(l["rank"] <= 3 for l in r["logs"]))),
            ("ログ調査(何らかの経路)", cnt(lambda r: r["logs"])), ("リスク評価", cnt(lambda r: r["risk"])),
            ("確認済み(脅威系一次資料あり)", cnt(lambda r: r["certainty"] == "確認済み"))]
    L = ["# VALIDATION_REPORT（自動生成: tools/build_index.py）", "", f"- データ最終検証日: {latest}",
         f"- 収録: 詳細付きポート {n} 件 / IANA 登録ポート {len(iana)} 件",
         "- レコード総数: " + ", ".join(f"{k} {len(v)}" for k, v in db.items()),
         f"- 整合性検証: **{'FAIL' if errors else 'PASS'}**（errors={len(errors)}, warnings={len(warnings)}）", "",
         "## 詳細付きポートの到達率", "", "| 項目 | 件数 |", "|---|---|"] + [f"| {a} | {b} |" for a, b in rows]
    L += ["", "## ポート別の不足（データ追加の優先リスト）", "", "| ポート | サービス | 不足 |", "|---|---|---|"]
    L += [f"| {r['n']}/{r['t']} | {r['service']} | {'、'.join(r['gaps'])} |" for r in ports if r["gaps"]]
    L += ["", "## エラー・警告", ""] + [f"- ERROR {e}" for e in errors] + [f"- WARN {w}" for w in warnings] + (["- なし"] if not errors + warnings else [])
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    db = load_all(ROOT / "data")
    errors, warnings = validate(db)
    if errors:
        print("\n".join(errors)); print("validation failed; assets not built"); sys.exit(1)
    ports, kb = build(db)
    iana = iana_rows()
    kb["meta"] = {"verified": max(r["verified_date"] for r in db["ports"]),
                  "attack_version": db["sources"][[s["source_id"] for s in db["sources"]].index(f"SRC-MITRE-{db['mitre_techniques'][0]['id']}")]["document_type"],
                  "iana_fetched": (ROOT / "data/raw/iana/FETCHED_AT").read_text().strip(), "detailed": len(ports), "iana": len(iana)}
    (ROOT / "docs/VALIDATION_REPORT.md").write_text(report(db, ports, iana, errors, warnings), encoding="utf-8")
    for out in (ROOT / "dist", ROOT / "app/assets/data"):
        out.mkdir(parents=True, exist_ok=True)
        for name, data in [("ports", ports), ("kb", kb), ("iana", iana)]:
            (out / f"{name}.json").write_text(json.dumps(data, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"assets: ports {len(ports)} / iana {len(iana)} / techniques {len(kb['techniques'])} / dets {len(kb['dets'])}")
